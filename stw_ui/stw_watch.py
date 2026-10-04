"""登录/进图监视线程（重构 v2.1 §8）：启动或附加游戏、启动 _sa_reader.py、
读 sa_reader_state.json、识别账号、等待 state==9 后向 UI 队列发事件。

职责（§8）：进程选择 / 启动·复用 PID / 启动 _sa_reader.py /
读取 sa_reader_state.json / 识别账号 / 等待 state==9 / 向 UI queue 发事件。
不允许：Frida attach、发送 fid14、发送 walk、解析战斗、修改 Tk 控件。

C1 硬边界：state==9 之前 Engine 尚未创建、Frida 尚未 attach（启动阶段零注入）。
C2：只发 phase / state / account / ready / dead / log 六种事件；
    UI 收到 ready 才创建 Engine。

依赖链（§2.1）：process <- watch <- ui。本模块只依赖 stw_config / stw_process /
psutil 及标准库，绝不 import stw_ui。
"""
import json
import os
import subprocess
import sys
import threading
import time
import traceback

import psutil

from stw_config import GAME_ARGS, GAME_CWD, GAME_EXE, STATE_TXT
from stw_process import fmt_client, hb, launch_game, list_clients


class Watcher(threading.Thread):
    """启动/附加游戏，扫描 L2 密钥，等 state==9 后通知界面解锁。"""

    def __init__(self, q, attach_existing: bool, args: str = GAME_ARGS,
                 pid: int = 0, launched_pid: int = 0):
        super().__init__(daemon=True)
        self.q = q
        self.attach_existing = attach_existing
        self.args = (args or "").strip()
        self.explicit_pid = pid
        # UI 已经拉起游戏时传进来，Watcher 复用它，绝不重复启动第二个实例
        self.launched_pid = launched_pid
        self.stop_flag = threading.Event()
        self.proc = None
        self.tracer = None

    def run(self):
        """外壳：监视线程绝不许把控制台带崩，异常一律只记不抛。"""
        try:
            self._run()
        except Exception as e:
            self.q.put(("log", "warn",
                        f"监视线程异常（控制台不会退出）：{type(e).__name__}: {e}"))
            self.q.put(("log", "dim", traceback.format_exc()[-600:]))
            self.q.put(("dead", None))

    def _auto_pick(self):
        """挑一个不是 STW 拉起来的客户端；有多个就挑开得最久的那个并提示。"""
        rows = [r for r in list_clients() if not r["blocked"]]
        for r in list_clients():
            self.q.put(("log", "dim", "  候选 " + fmt_client(r)))
        if not rows:
            return 0
        if len(rows) > 1:
            self.q.put(("log", "warn",
                        f"  有 {len(rows)} 个非 STW 客户端，自动选了开得最久的 "
                        f"PID={rows[0]['pid']}；不确定就在上面列表里手动选"))
        return rows[0]["pid"]

    def _run(self):
        g = None
        try:
            try:
                if self.attach_existing:
                    pid = self.explicit_pid or self._auto_pick()
                    if not pid:
                        self.q.put(("log", "warn",
                                    "没有可附加的客户端（现有的全是 STW 拉起来的）"))
                        self.q.put(("dead", None))
                        return
                    self.q.put(("log", "sys", f"附加到已运行的客户端 PID={pid}"))
                    self.q.put(("phase", f"已附加 PID={pid}，等待进入地图…"))
                elif self.launched_pid:
                    # UI 已经拉起过游戏，Watcher 直接复用这个 PID。
                    # ⚠ 这里绝不能再 launch_game——否则一次点击会开出两个
                    # sa_2903.exe（实测 PID 51536 与 56904 同秒出现）
                    pid = self.launched_pid
                    self.q.put(("log", "sys",
                                f"复用已拉起的游戏 PID={pid}（不重复启动）"))
                    self.q.put(("phase", f"PID={pid} 已启动，等待进入地图…"))
                else:
                    self.q.put(("phase", "正在启动 sa_2903.exe …"))
                    self.q.put(("log", "sys", f"命令行：{GAME_EXE} {self.args}"))
                    self.q.put(("log", "sys", f"工作目录：{GAME_CWD}"))
                    pid, how, proc = launch_game(GAME_EXE, self.args, GAME_CWD)
                    self.proc = proc
                    self.q.put(("log", "sys", f"已拉起游戏 PID={pid} 方式={how}"))
                    self.q.put(("phase", f"游戏已启动 PID={pid}，等待窗口…"))
                    # （v2.1 §B1：launch_game 恒 DEVNULL，没有管道可泵，
                    #   旧 _pump 及其死分支已删，勿再接回）
                    # ⚠ 这里绝对不能挂 frida！游戏在「进入世界(state→9)」的瞬间
                    # 会做一次性注入扫描：此刻进程里有 frida agent，游戏就自尽
                    # 并顺手杀掉注入宿主（我们的控制台）。实测 Tracer 提前挂 =
                    # 一到 state=9 控制台闪退、游戏也消失。之前 120s/8 场能跑，
                    # 是因为 frida 是在已经在地图里之后才附加的，躲过了那次扫描。
                    self.q.put(("log", "sys",
                                "  启动阶段零注入（frida 等点「开始」才挂）"))
            except Exception as e:
                self.q.put(("log", "warn", f"启动失败：{type(e).__name__}: {e}"))
                self.q.put(("dead", None))
                return

            account = None
            last_scan = 0.0
            ready_sent = False

            # ⚠ 控制台自己绝不能 OpenProcess 读游戏：实测游戏进入世界(state→9)
            # 会硬杀持有其句柄的外部进程（无 atexit 记录）。STW 是父进程却没事，
            # 说明触发条件是"句柄"不是"父子"。故把读取放到独立进程 _sa_reader.py，
            # 控制台只读它写的 JSON；读取进程被杀也不影响界面。
            STATE_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "sa_reader_state.json")
            _here = os.path.dirname(os.path.abspath(__file__))
            # _sa_reader.py 可能被整理进了 shit/，主目录没有就去那边找
            reader = os.path.join(_here, "_sa_reader.py")
            if not os.path.exists(reader):
                _alt = os.path.join(_here, "shit", "_sa_reader.py")
                if os.path.exists(_alt):
                    reader = _alt

            def spawn_reader():
                try:
                    if os.path.exists(STATE_JSON):
                        os.remove(STATE_JSON)
                except Exception:
                    pass
                return subprocess.Popen(
                    [sys.executable, reader, "--pid", str(pid)],
                    cwd=os.path.dirname(reader),
                    creationflags=0x00000008 | 0x01000000 | 0x08000000,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            rp = spawn_reader()
            self.reader_proc = rp          # 关控制台时要一起收掉
            self.q.put(("log", "sys",
                        f"已启动独立读取进程 PID={rp.pid}（控制台不再直接读游戏）"))

            while not self.stop_flag.is_set():
                if not psutil.pid_exists(pid):
                    rc = self.proc.poll() if self.proc is not None else None
                    why = {0xC0000005: "STATUS_ACCESS_VIOLATION（访问违例）",
                           0xC0000006: "STATUS_IN_PAGE_ERROR",
                           0xC0000135: "STATUS_DLL_NOT_FOUND",
                           0xC0000142: "STATUS_DLL_INIT_FAILED",
                           0xC0000409: "STATUS_STACK_BUFFER_OVERRUN"}.get(rc, "")
                    self.q.put(("log", "warn",
                                f"!! 游戏进程没了 (PID={pid})"
                                + (f" 退出码 {rc} (0x{rc & 0xFFFFFFFF:08X}) {why}"
                                   if rc is not None else "（非子进程，取不到退出码）")))
                    self.q.put(("dead", None))
                    return

                # 读取进程若被游戏杀掉，界面要活着重拉，不能跟着退出
                if rp.poll() is not None:
                    self.q.put(("log", "warn",
                                "读取进程被结束（游戏进入世界时会杀持有句柄者）"
                                "— 界面存活，正在重拉…"))
                    rp = spawn_reader()
                    self.reader_proc = rp
                    time.sleep(1.0)
                    continue

                try:
                    with open(STATE_JSON, encoding="utf-8") as f:
                        d = json.load(f)
                except Exception:
                    time.sleep(0.5)
                    continue

                if not d.get("alive"):
                    self.q.put(("dead", None))
                    return

                st = d.get("state")
                s = {"state": st, "x": d.get("x"), "y": d.get("y"),
                     "map": d.get("map")}
                self.q.put(("state", (pid, s)))
                hb("监听循环", state=st, pid=pid)

                acc = d.get("account")
                if acc and account is None:
                    account = acc
                    self.q.put(("log", "sys", f"识别到账号 {account}"))
                    self.q.put(("account", (account, [account])))

                if account and st == 9:
                    self.q.put(("phase",
                                f"已进游戏（账号 {account}）— 战斗监听中"
                                "（是否自动执行由底部按钮决定）"))
                    if not ready_sent:
                        self.q.put(("ready", {"pid": pid, "account": account}))
                        ready_sent = True
                elif account:
                    self.q.put(("phase", f"账号 {account} · "
                                         f"{STATE_TXT.get(st, st)} — 等待进入地图"))
                else:
                    self.q.put(("phase", f"{STATE_TXT.get(st, st)} — "
                                         f"等待你在登录界面输入账号"))
                time.sleep(2.0)
        except Exception as e:
            self.q.put(("log", "warn",
                        f"监听循环异常（控制台不会退出）：{type(e).__name__}: {e}"))
            self.q.put(("log", "dim", traceback.format_exc()[-600:]))
        finally:
            if g:
                try:
                    g.close()
                except Exception:
                    pass
