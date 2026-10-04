"""游戏进程服务（重构 v2.1 §7）：客户端列表、启动游戏、Job Object 检测、
加速补丁；文末附「控制台黑匣子」心跳/退出探针（watch 与 ui 共用——放依赖链
底层，避免 stw_watch 为了 hb 反向依赖 stw_ui）。

只迁「当前实际运行路径」（v2.1 §4）：现行启动方式是 launch_game() 直拉；
launch_game_detached()（explorer detached）原样保留为备用实现，但重构期间
**不切换启动策略**——是否改回 detached 是独立的功能变更任务，不跟结构
重构混在一起。
允许依赖：stw_config / psutil / ctypes / subprocess / atexit / os /
auto_encounter / fast_encounter；禁止依赖 stw_ui / stw_battle / stw_engine。
"""
import atexit
import ctypes
import os
import subprocess
import time

import psutil

# ⚠ stw_config 必须最先导入：它负责把 BASE_DIR / shit/ 注册进 sys.path
from stw_config import HEARTBEAT

import auto_encounter as ae  # noqa: E402
import fast_encounter as fe  # noqa: E402


# ---------------------------------------------------------------------------
# 客户端列表 / 启动（Job Object 相关的大坑见下）
# ---------------------------------------------------------------------------
def list_clients():
    """列出所有 sa_2903.exe，标注父进程。STW 拉起来的排在最后且标为禁用。"""
    try:
        blocked = set(fe.stw_child_pids())
    except Exception:
        blocked = set()
    rows = []
    for p in psutil.process_iter(["pid", "name", "create_time"]):
        if (p.info["name"] or "").lower() != "sa_2903.exe":
            continue
        pid = p.info["pid"]
        try:
            par = psutil.Process(pid).parent()
            pname = par.name() if par else "?"
        except Exception:
            pname = "?"
        rows.append({"pid": pid, "parent": pname,
                     "blocked": pid in blocked,
                     "age": time.time() - (p.info["create_time"] or 0)})
    rows.sort(key=lambda r: (r["blocked"], -r["age"]))
    return rows


def fmt_client(r):
    m, s = int(r["age"] // 60), int(r["age"] % 60)
    tag = "STW的·禁止操作" if r["blocked"] else "可操作"
    return f"PID {r['pid']:<7} 父={r['parent']:<14} 已开 {m}分{s:02d}秒  [{tag}]"


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32)]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in
                ("ReadOperationCount", "WriteOperationCount",
                 "OtherOperationCount", "ReadTransferCount",
                 "WriteTransferCount", "OtherTransferCount")]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]


def job_flags():
    """控制台所在 Job 的三个关键位：(在Job里, 关闭即杀, 允许逃逸)。

    这是"游戏闪退"最阴的一种成因：从某些终端/沙箱里启动控制台时，系统会把它
    塞进带 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 的 Job。游戏作为子进程也在里面，
    于是控制台/命令一结束，游戏在 1 秒内被系统杀掉——看起来就像登录完闪退。
    手动双击 .bat 开的通常不在，但也有例外，所以每次都实测。
    """
    try:
        k = ctypes.windll.kernel32
        k.GetCurrentProcess.restype = ctypes.c_void_p
        k.IsProcessInJob.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.POINTER(ctypes.c_bool)]
        k.IsProcessInJob.restype = ctypes.c_bool
        res = ctypes.c_bool(False)
        if not k.IsProcessInJob(k.GetCurrentProcess(), None, ctypes.byref(res)):
            return False, False, False
        if not res.value:
            return False, False, False
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        ok = k.QueryInformationJobObject(None, 9, ctypes.byref(info),
                                         ctypes.sizeof(info), None)
        f = info.BasicLimitInformation.LimitFlags if ok else 0
        return True, bool(f & 0x2000), bool(f & 0x800)
    except Exception:
        return False, False, False


def in_kill_job():
    return job_flags()[1]


def launch_game_detached(exe, args_str, cwd, timeout=25.0):
    """拉起游戏，但**不让控制台当它的父进程**。返回新进程 PID（0=未发现）。

    实测依据（2026-09-28 07:46）：
    - 控制台（游戏的父进程）在游戏进入世界时被硬杀，且无 atexit 记录
    - 同时运行的独立读取进程（持有游戏句柄、但不是父进程）**活了下来**
    → 触发条件是"父子关系"，不是"持有句柄"。所以用 `cmd /c start` 让
      explorer 去拉起游戏：控制台仍是发起方，但游戏归 explorer 管。
    """
    import psutil

    def snapshot():
        return {p.info["pid"] for p in psutil.process_iter(["pid", "name"])
                if (p.info["name"] or "").lower() == "sa_2903.exe"}

    before = snapshot()
    argv = ["cmd", "/c", "start", "", exe] + args_str.split()
    subprocess.Popen(argv, cwd=cwd,
                     creationflags=0x08000000,      # CREATE_NO_WINDOW
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + timeout
    while time.time() < deadline:
        diff = snapshot() - before
        if diff:
            return sorted(diff)[0]
        time.sleep(0.5)
    return 0


def launch_game(exe, args_str, cwd):
    """拉起游戏。返回 (pid, 提示语, proc)。

    STW 拉起 sa.exe 不会被干掉，控制台同样可以直接 Popen 拉——此前担心的
    「控制台 Tk 会被游戏连带退出」已被用户实测推翻，因此恢复直拉方式。
    stdout/stderr 一律 DEVNULL：游戏从不往 stdout 写东西，接管道只添风险。
    """
    argv = [exe] + args_str.split()
    kw = dict(cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    injob, kill, brk = job_flags()
    if injob and kill:
        try:
            p = subprocess.Popen(argv, creationflags=0x01000000, **kw)
            return p.pid, "子进程(BREAKAWAY 逃出 Job)", p
        except OSError:
            pass
    p = subprocess.Popen(argv, **kw)
    return p.pid, "子进程(Popen)", p


# 加速移动 = STW 的 move + ui 两组补丁，共 21 个。
# fast_move.py 里已验证：只打 move 那 10 个看不出加速，
# 必须连 ui 组那 11 个一起打（去掉界面等待）才有 STW 级别的速度。
SPEED_GROUPS = ae.PATCH_GROUPS  # ("move", "ui")


def apply_speed_patch(pid, enable=True):
    """打上/还原 STW 加速移动补丁（move+ui 共 21 个）。

    返回 (ok, msgs)。只操作非 STW 子进程的那个客户端。
    """
    msgs = []
    try:
        try:
            if ae._is_stw_child(pid):
                return False, [f"拒绝操作：PID={pid} 是 STW0.30.exe 的子进程"]
        except Exception:
            pass
        g = ae.Game(pid, writable=True)
    except Exception as e:
        return False, [f"打开进程失败：{type(e).__name__}: {e}"]
    try:
        changed = 0
        already = 0
        errs = 0
        for group in SPEED_GROUPS:
            for addr, orig, patched, desc in ae.PATCHES[group]:
                src = bytes.fromhex(patched if not enable else orig)
                dst = bytes.fromhex(orig if not enable else patched)
                a = g.abs(addr)
                try:
                    cur = g.read_bytes(a, len(src))
                except Exception as e:
                    errs += 1
                    msgs.append(f"0x{addr:06X} {desc} 读不到({e})，跳过")
                    continue
                if cur == dst:
                    already += 1
                    continue
                if cur != src:
                    msgs.append(f"0x{addr:06X} {desc} 字节不符"
                                f"({cur.hex().upper()})，跳过")
                    continue
                g.write_bytes(a, dst)
                changed += 1
        head = ("加速移动已开启，改写 %d 处（已是补丁态 %d 处）" if enable
                else "加速移动已还原，还原 %d 处（本就原始 %d 处）") % (changed, already)
        msgs.insert(0, head)
        # 个别地址读不到不算彻底失败，只要真的改成了就当成功
        return (errs == 0 or changed > 0), msgs
    except Exception as e:
        return False, [f"补丁失败：{type(e).__name__}: {e}"]
    finally:
        try:
            g.close()
        except Exception:
            pass


def speed_state(pid):
    """只读：核对加速补丁当前是「原始」还是「已打补丁」。返回 (统计, 明细)。"""
    try:
        g = ae.Game(pid, writable=False)
    except Exception as e:
        return None, [f"打开进程失败：{type(e).__name__}: {e}"]
    try:
        n = {"p": 0, "o": 0, "x": 0}
        lines = []
        for group in SPEED_GROUPS:
            for addr, orig, patched, desc in ae.PATCHES[group]:
                a = g.abs(addr)
                try:
                    cur = g.read_bytes(a, len(bytes.fromhex(orig))).hex().upper()
                except Exception as e:
                    n["x"] += 1
                    lines.append(f"[{group}] 0x{addr:06X} {desc} 读不到({e})")
                    continue
                if cur == patched.upper():
                    n["p"] += 1
                    st = "已打补丁"
                elif cur == orig.upper():
                    n["o"] += 1
                    st = "原始"
                else:
                    n["x"] += 1
                    st = "其它"
                lines.append(f"[{group}] 0x{addr:06X} {desc} {cur} {st}")
        return n, lines
    finally:
        try:
            g.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 黑匣子：不管控制台怎么死（异常/段错误/被杀），都能看出死在哪一步
# ---------------------------------------------------------------------------
HB = {"step": "刚启动", "state": "-", "pid": "-"}


def hb(step, **kw):
    """更新心跳状态。线程安全：只做赋值，写盘由心跳线程统一做。"""
    HB.update(kw, step=step, t=time.time())


def hb_thread():
    n = 0
    # 追加写：控制台重启后保留上一轮死前现场，不再覆盖证据
    try:
        with open(HEARTBEAT, "a", encoding="utf-8") as f:
            f.write(f"\n==== {time.strftime('%F %T')} heartbeat start "
                    f"pid={os.getpid()} ====\n")
    except Exception:
        pass
    while True:
        time.sleep(1.0)
        n += 1
        try:
            with open(HEARTBEAT, "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%H:%M:%S')}  step={HB.get('step')}  "
                        f"state={HB.get('state')}  pid={HB.get('pid')}  "
                        f"beat#{n}\n")
        except Exception:
            pass


def install_exit_probe():
    """死因自证探针：进程无论怎么结束都尽量留一句话。

    之前最大的盲区是"进程消失但没有任何 Python 异常、事件日志也没记录"，
    分不清是被外部杀还是正常退出。这里用 atexit 把最后一步写进 stw_exit.txt；
    如果 stw_exit.txt 没有本次 pid 的记录，而进程没了，就是被外部强杀。
    """

    def _report():
        try:
            with open("stw_exit.txt", "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%F %T')}] pid={os.getpid()} "
                        f"last_step={HB.get('step')} "
                        f"state={HB.get('state')} "
                        f"watched_pid={HB.get('pid')} via=atexit\n")
        except Exception:
            pass

    atexit.register(_report)
