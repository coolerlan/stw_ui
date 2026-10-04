"""战斗监听 / 自动执行 解耦测试 —— 对应 state9_battle_hook_separation_design.md

要点：**监听永远在线，执行由用户控制。**

不连游戏，也不改协议逻辑：直接把真实的 Engine 跑起来，只把 frida / 网桥 /
内存快照换成假的，然后喂真实的报文进去，看它到底发不发。

    Case 1  只监听（没点开始）：收包 + 解析，但 fid=14 / fid=1 一个都不发
    Case 2  点「开始自动战斗」：立刻（含监听期间积压的窗口）按策略发 fid=14
    Case 3  点「停止自动战斗」：停止代发，但监听继续在线（收包/更新状态）
    Case 4  停止后再开始：不需要重新 Hook，恢复代发

另外回归两条硬约束：
    · 停止时绝不 close hook / reset socket / 退出 state9
    · 开始时不重新 Hook、不清战斗状态（BC/BA/回合状态沿用）
"""
import os
import queue
import sys
import tempfile
import time

# 仓库根 + stw_ui 包目录进 sys.path（从 __file__ 推，不写死绝对路径）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "stw_ui"))
sys.path.insert(0, _ROOT)
from stw_ui import stw_ui                                  # noqa: E402
import stw_engine                                 # noqa: E402
from stw_engine import Engine                        # noqa: E402

sa = stw_engine.sa

# 别把真实日志冲掉：run() 每次开跑都会 open(LOG, "w")
stw_engine.LOG = os.path.join(tempfile.gettempdir(), "_test_hooksep_log.jsonl")

ACCOUNT = "testacct"
KEY = sa.make_l2_key(ACCOUNT)

# 真实 BC 报文（来自 _test_slot.py 的样本）：我方 0/5，敌方 F/10/11/12/13
BC_RAW = (
    "BC|0|0|UV2D||18AD7|8C|4E1|5A9|5|1|巴朵兰恩|8C|40E|55A|"
    "5|min-1||187B2|80|41F|4E3|1|0||0|0|0|"
    "F|加宝格恩||18809|5A|2CA|2CA|1|0||0|0|0|"
    "10|加宝格恩||18809|58|2BB|2BB|1|0||0|0|0|"
    "11|加宝格恩||18809|5A|2D9|2D9|1|0||0|0|0|"
    "12|加宝格恩||18809|58|2B3|2B3|1|0||0|0|0|"
    "13|加宝格恩||18809|58|2A5|2A5|1|0||0|0|0|"
)


class FakeApi:
    def __init__(self):
        self.q = []

    def dump(self):
        out, self.q = self.q, []
        return out


class FakeBridge:
    def __init__(self):
        self.sent = []

    def send(self, b):
        self.sent.append(b)

    def status(self):
        return {"ready": True, "socket": 1}

    def close(self):
        pass


class FakeGame:
    def snapshot(self):
        return {"state": 9, "x": 10, "y": 10, "map": 999999}

    def close(self):
        pass


def frame(fid, payload):
    """组装一个入站帧（和服务器下来的格式一致）。"""
    msg = b"&;" + str(fid).encode() + b";" + sa.enstring(payload, KEY) + b";#;"
    return {"hex": stw_engine.enc(msg).hex(), "dir": "IN"}


def fid_of(b):
    try:
        return sa.decode_layer1(b).split(b";")[1].decode()
    except Exception:
        return "?"


def cmds_of(bridge):
    """解出所有代发的 fid=14 指令内容（H|F / W|1|F / E / T|x …）。"""
    out = []
    for b in bridge.sent:
        try:
            p = sa.decode_layer1(b).split(b";")
        except Exception:
            continue
        if p[1] != b"14":
            continue
        out.append(sa.destring(p[2], KEY).decode("gb18030", "replace"))
    return out


# ---------------------------------------------------------------------------
# 把 Engine 的「外部依赖」换成假的：frida / 网桥 / 内存快照
# ---------------------------------------------------------------------------
def fake_setup(self):
    self.pid = 0
    self.key = KEY
    self.api = FakeApi()
    self.b = FakeBridge()
    self.g = FakeGame()
    self.sess = None
    self.sn = None
    self.snc = None
    self.hook_sc = None
    self.hook_calls = []          # 记录 set_hook 的每一次调用


def fake_set_hook(self, on):
    # 必须照抄真实 set_hook 的幂等守卫：主循环每轮都会调一次，
    # 只有状态真的翻转才算「重新 Hook」
    if getattr(self, "hook_on", None) == on:
        return
    self.hook_on = on
    self.hook_calls.append(bool(on))


Engine.setup = fake_setup
Engine.set_hook = fake_set_hook


def start_engine(mode="attack"):
    q = queue.Queue()
    cfg = {"pid": 0, "account": ACCOUNT, "accounts": [ACCOUNT],
           "fast_enc": True, "fast_battle": True, "mode": mode,
           "interval": 0.1, "secs": 100000.0, "maxb": 999,
           "show46": False, "showraw": False,
           "catch": {"rules": {}, "no_match_action": "flee",
                     "pet_action": "attack", "after_success": "continue",
                     "stop_count": 1}}
    e = Engine(cfg, q)
    e.auto_ev.clear()             # 默认只监听
    e.start()
    for _ in range(100):
        if e.battle_hook_active:
            break
        time.sleep(0.05)
    return e, q


def feed(e, *frames, wait=0.45):
    e.api.q.extend(frames)
    time.sleep(wait)


def drain(q):
    out = []
    try:
        while True:
            out.append(q.get_nowait())
    except queue.Empty:
        pass
    return out


def kinds(items):
    return [i[0] for i in items]


# ===========================================================================
print("=" * 70)
print("战斗监听 / 自动执行 解耦测试")
print("=" * 70)

e, q = start_engine("attack")
assert e.battle_hook_active, "进入之后监听必须自动挂上"
assert not e.auto_ev.is_set(), "默认必须是「只监听、不代发」"
drain(q)
print("OK 启动：battle_hook_active=True，battle_auto_active=False")

# ---- Case 1：只监听，不点开始 ----
print("\n--- Case 1：只监听（未点开始自动战斗）---")
feed(e, frame(7, "7|1|"),
        frame(15, BC_RAW),
        frame(15, "BA|18000|1|"))
items = drain(q)
sent_fid = [fid_of(b) for b in e.b.sent]
n14 = sent_fid.count("14")
n1 = sent_fid.count("1")
print(f"   收到界面事件：{sorted(set(kinds(items)))}")
print(f"   已发报文 fid 分布：{ {f: sent_fid.count(f) for f in set(sent_fid)} }")
assert "battle_units" in kinds(items), "监听期间必须正常解析 BC 并更新队伍数据"
assert n14 == 0, f"只监听时不许发任何 fid=14（实际 {n14}）"
assert n1 == 0, f"只监听时不许发任何走位包 fid=1（实际 {n1}）"
assert e.battle_hook_active, "监听必须仍然在线"
print("OK Case 1：BC/BA 正常解析，fid=14 / fid=1 一个都没发")

# ---- Case 2：点「开始自动战斗」----
print("\n--- Case 2：点击开始自动战斗 ---")
hooks_before = len(e.hook_calls)
e.auto_ev.set()
time.sleep(0.6)
sent_fid = [fid_of(b) for b in e.b.sent]
n14 = sent_fid.count("14")
cmds = cmds_of(e.b)
print(f"   已发 fid=14 指令：{cmds}")
assert n14 >= 2, f"开启后必须代发一轮（角色+宠物两条），实际 {n14}"
assert any(c.startswith("H|") for c in cmds), cmds
assert any(c.startswith("W|1|") for c in cmds), cmds
assert len(e.hook_calls) == hooks_before, "点击开始不许重新 Hook"
print("OK Case 2：不重新 Hook，直接用监听期间积压的 BA low=0 窗口发了指令")

# ---- Case 2b：已经开启时，新到的 BA low=0 也要正常执行 ----
print("\n--- Case 2b：开启状态下新到的 BA low=0 ---")
feed(e, frame(15, "BH|a10|rF|fA|d1|p0|FF|"),     # BH 结算解锁本轮
        frame(15, "BA|18000|2|"))                # low=0 新窗口
n_2b = [fid_of(b) for b in e.b.sent].count("14")
print(f"   fid=14 累计：{n_2b}")
assert n_2b >= 4, f"新窗口必须再代发一轮（实际累计 {n_2b}）"

# ---- Case 3：点「停止自动战斗」----
print("\n--- Case 3：战斗中点击停止自动战斗 ---")
n_before = n_2b
e.auto_ev.clear()
# BH 结算解锁本轮，再给一个新的 BA low=0：停止状态下必须继续收包但不代发
feed(e, frame(15, "BH|a10|rF|fA|d1|p0|FF|"),
        frame(15, "BA|18000|3|"))
items = drain(q)
sent_fid = [fid_of(b) for b in e.b.sent]
n_after = sent_fid.count("14")
print(f"   停止后又收到的界面事件：{sorted(set(kinds(items)))}")
print(f"   fid=14 数量：{n_before} -> {n_after}（必须不变）")
assert n_after == n_before, "停止后不许再代发 fid=14"
assert any(i[0] == "log" and i[1] == "battle" for i in items), \
    "停止后仍要解析战斗包（监听在线）"
assert e.battle_hook_active, "停止不许关掉监听（不 close hook / 不 reset socket）"
assert e.is_alive(), "停止不许退出引擎 / 退出 state9"
print("OK Case 3：停止代发但监听继续在线，战斗包照常解析")

# ---- Case 4：停止后再次开始 ----
print("\n--- Case 4：停止后再次开始 ---")
hooks_before = len(e.hook_calls)
e.auto_ev.set()
time.sleep(0.6)
sent_fid = [fid_of(b) for b in e.b.sent]
n_restart = sent_fid.count("14")
print(f"   再次开始后 fid=14 总数：{n_restart}（>{n_after} 才算恢复）")
assert n_restart > n_after, "再次开始必须立刻恢复代发"
assert len(e.hook_calls) == hooks_before, "再次开始也不需要重新 Hook"
assert e.battle_hook_active and e.is_alive()
print("OK Case 4：无需重新 Hook，恢复自动战斗")

# ---- 停止时不会破坏状态：战斗状态仍在维护 ----
print("\n--- 附加：停止期间收到 BE 也要正常清理战斗状态 ---")
e.auto_ev.clear()
feed(e, frame(15, "BE|1|"))
s = drain(q)
print(f"   界面事件：{sorted(set(kinds(s)))}")
assert e.is_alive() and e.battle_hook_active
print("OK 停止期间 BE 正常收尾，不影响下一次开始")

e.stop_flag.set()
e.join(timeout=5)

# ===========================================================================
# Case 5：停止后的「地图/NPC 同步保护」
#   RUNNING -> STOP_PENDING ->（战斗结束）MAP_SYNC_WAIT ->（fid41/37/4 ≥2
#   + 1.5s 稳定等待）STOPPED_READY
# ===========================================================================
print("\n--- Case 5：停止后的地图/NPC 同步 ---")
# Engine 剥离后这些常量不再由 stw_ui 转手导出，直接从 stw_config 取
from stw_config import (STOP_RUNNING, STOP_PENDING,  # noqa: E402
                        MAP_SYNC_WAIT, STOPPED_READY, MAP_SYNC_SCORE_NEED,
                        MAP_READY_DELAY)

e2, q2 = start_engine("attack")
# 进一场战斗并开启自动执行
feed(e2, frame(7, "7|1|"), frame(15, BC_RAW), frame(15, "BA|18000|1|"))
e2.auto_ev.set()
time.sleep(0.5)
assert e2.stop_phase == STOP_RUNNING, e2.stop_phase
n_at_stop = [fid_of(b) for b in e2.b.sent].count("14")
print(f"   运行中：stop_phase={e2.stop_phase}，已发 fid=14 {n_at_stop}")

# 点停止：进入 STOP_PENDING（战斗还没结束，不许清空状态/关 Hook/强制 fid=8）
e2.auto_ev.clear()
time.sleep(0.4)
assert e2.stop_phase == STOP_PENDING, e2.stop_phase
print(f"   点停止：stop_phase={STOP_PENDING}（战斗内，等待自然结束）")

# 战斗结束（BE）-> MAP_SYNC_WAIT
# ⚠ finish() 补发 fid=8 后会 sleep(1.0)，等待必须比它长
feed(e2, frame(15, "BE|1|"), wait=1.8)
assert e2.stop_phase == MAP_SYNC_WAIT, e2.stop_phase
print(f"   收到 BE：stop_phase={MAP_SYNC_WAIT}（等 fid=41/37/4）")

# 同步包计分：1 个不够（fid=41 里带地图对象/NPC）
feed(e2, frame(41, "1|24V|355|341|5|101099|134|2|UV2B||1|1|0|hwnd|巴朵兰恩|129"
                   ",22|tV|14|13|5|16062|1|0|战斗指导员||1|1|0|||0"
                   ",12|nw|14|16|6|16039|1|0|村长的秘书||1|1|0|||0"))
assert e2.stop_phase == MAP_SYNC_WAIT
assert e2.map_sync_score == 1, e2.map_sync_score
# NPC 必须被解出来（用户要的就是"地图里的 NPC 能显示"）
assert e2.map_objects and "战斗指导员" in [o["name"] for o in e2.map_objects], \
    e2.map_objects
print(f"   解出地图对象 {len(e2.map_objects)} 个："
      f"{[o['name'] for o in e2.map_objects]}")
time.sleep(MAP_READY_DELAY + 0.4)
assert e2.stop_phase == MAP_SYNC_WAIT, "只收到 1 个同步包不许认为同步完成"
print(f"   1 个同步包：score={e2.map_sync_score}，仍在等待（正确）")

# 第 2 个同步包 -> 分数够了 -> 再等 1.5s -> STOPPED_READY
n_before_sync = [fid_of(b) for b in e2.b.sent].count("14")
feed(e2, frame(37, "37|24V|"), wait=0.2)
assert e2.map_sync_score >= MAP_SYNC_SCORE_NEED, e2.map_sync_score
time.sleep(MAP_READY_DELAY + 0.6)
assert e2.stop_phase == STOPPED_READY, e2.stop_phase
n_after_sync = [fid_of(b) for b in e2.b.sent].count("14")
assert n_after_sync == n_before_sync, "停止流程期间不许代发任何 fid=14"
assert e2.battle_hook_active and e2.is_alive(), "停止后监听必须仍然在线"
print(f"   2 个同步包 + {MAP_READY_DELAY}s：stop_phase={STOPPED_READY}"
      f"（监听在线，未再发 fid=14）")

# 再次开始 -> 回到 RUNNING（无需重挂 Hook）
hooks2 = len(e2.hook_calls)
e2.auto_ev.set()
time.sleep(0.3)
assert e2.stop_phase == STOP_RUNNING, e2.stop_phase
assert len(e2.hook_calls) == hooks2
print("OK Case 5：停止后不会再卡在'等待'，恢复运行也无需重新 Hook")
e2.stop_flag.set()
e2.join(timeout=5)

# ===========================================================================
# 界面层：按钮只切换「自动执行」，不再负责挂载监听 / 停引擎
# ===========================================================================
print("\n--- 界面：开始/停止按钮职责 ---")
import threading                                   # noqa: E402
import tkinter as tk                               # noqa: E402

app = stw_ui.App()
app.update()
assert app.btn.cget("text") == "开始自动战斗", app.btn.cget("text")


class StubEng:
    def __init__(self):
        self.auto_ev = threading.Event()
        self.stop_flag = threading.Event()

    def is_alive(self):
        return True


app.eng = StubEng()
app.ready = True
app.hook_ready = True

app._toggle()                       # 第一次点 -> 开启自动执行
assert app.eng.auto_ev.is_set()
assert app.btn.cget("text") == "停止自动战斗", app.btn.cget("text")
assert not app.eng.stop_flag.is_set(), "停止按钮不许停引擎"

app._toggle()                       # 再点 -> 只关执行，监听继续
assert not app.eng.auto_ev.is_set()
assert app.btn.cget("text") == "开始自动战斗", app.btn.cget("text")
assert not app.eng.stop_flag.is_set(), "停止自动战斗 不许 close hook / 停引擎"
print("OK 按钮：只切 battle_auto_active，不重新 Hook、不停引擎、不退出 state9")

# 停止流程的三个提示文案（文档 §9：别让用户以为卡死）
app._drain_item(("stop_phase", (STOP_PENDING, "")))
assert "等待战斗结束" in app.v_exec.get(), app.v_exec.get()
app._drain_item(("stop_phase", (MAP_SYNC_WAIT, "1/2")))
assert "等待地图/NPC 同步 1/2" in app.v_exec.get(), app.v_exec.get()
app._drain_item(("map_objects", (3, "战斗指导员、村长的秘书")))
assert "地图/NPC：3 个" in app.v_npc.get(), app.v_npc.get()
app._drain_item(("stop_phase", (STOPPED_READY, "地图正常")))
assert "已停止" in app.v_exec.get(), app.v_exec.get()
print("OK 停止进度可见：", app.v_exec.get(), "|", app.v_npc.get())
app.destroy()

print("\nRESULT: PASS —— 监听永远在线，执行由用户控制")
