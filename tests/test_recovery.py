# -*- coding: utf-8 -*-
"""战后自动恢复 v1 测试（对应《战后自动恢复实施开发文档》§71 测试矩阵）。

重点验证的四件事：
1. 阈值与气力分支（缺 300 不治 / 缺 301 才治 / qi>30 直接治 / qi<=30 先用药）
2. 背包 2→15 扫描是 **Engine 全局状态**：判失败的槽位跨场次永不重试
3. 真的以「内存值上涨」当成功，而不是「包发出去了」
4. 恢复期间与遇敌 / 丢宠 / 停止 / 上限退出 的互斥

fid=57 的 target 已由用户确认：0=角色自己，1=K0 骑宠（原 target=4 实测 HP 不涨，作废）。
所以 T13 改为断言「K0 缺血时真的会发一条 target=1 的 fid=57」。
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

import stw_engine                                     # noqa: E402
from stw_engine import Engine                         # noqa: E402

sa = stw_engine.sa
stw_engine.LOG = os.path.join(tempfile.gettempdir(), "_test_recovery_log.jsonl")

# 让状态机的等待不至于把测试拖到几十秒（方法里读的是模块全局，可以现改）
stw_engine.RECOVERY_ACTION_TIMEOUT = 0.25
stw_engine.RECOVERY_WAIT_MAP_TIMEOUT = 0.4

ACCOUNT = "testacct"
KEY = sa.make_l2_key(ACCOUNT)

P_HP, P_MAX, P_QI = (stw_engine.PLAYER_HP_ADDR,
                     stw_engine.PLAYER_MAX_HP_ADDR,
                     stw_engine.PLAYER_QI_ADDR)
K_HP, K_MAX = stw_engine.K0_HP_ADDR, stw_engine.K0_MAX_HP_ADDR


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
    """读内存走 read_bytes(addr, 4)，与 ae.Game 已有的只读句柄同一形态。"""

    def __init__(self):
        self.mem = {}
        self.state = 9

    def snapshot(self):
        return {"state": self.state, "x": 60, "y": 54, "map": 999999}

    def read_bytes(self, addr, n):
        v = int(self.mem.get(int(addr), 0))
        return v.to_bytes(4, "little")[:n]

    def close(self):
        pass


def fake_setup(self):
    self.pid = 0
    self.key = KEY
    self.api = FakeApi()
    self.b = FakeBridge()
    self.g = FakeGame()
    self.sess = self.sn = self.snc = self.hook_sc = None


Engine.setup = fake_setup
Engine.set_hook = lambda self, on: None


def frame(fid, payload):
    msg = b"&;" + str(fid).encode() + b";" + sa.enstring(payload, KEY) + b";#;"
    return {"hex": stw_engine.enc(msg).hex(), "dir": "IN"}


def wait_until(pred, timeout=15.0, what=""):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if pred():
            return True
        time.sleep(0.03)
    raise AssertionError(f"等不到条件成立：{what}（{timeout}s）")


def stop(e):
    e.stop_flag.set()
    e.join(timeout=5)


def start_engine(fast_enc=False, mode="attack", maxb=999):
    q = queue.Queue()
    cfg = {"pid": 0, "account": ACCOUNT, "accounts": [ACCOUNT],
           "fast_enc": fast_enc, "fast_battle": True, "mode": mode,
           "interval": 0.1, "secs": 100000.0, "maxb": maxb,
           "show46": False, "showraw": False,
           "catch": {"rules": {}, "no_match_action": "flee",
                     "pet_action": "attack", "after_success": "continue",
                     "stop_count": 99, "drop_non_full": False,
                     "poison_enabled": False, "poison_skill": 2,
                     "poison_hp_ratio": 0.10, "poison_verify": "log",
                     "poison_dmg_mode": "derived"}}
    e = Engine(cfg, q)
    e.auto_ev.set()
    e.start()
    wait_until(lambda: e.battle_hook_active, what="引擎挂载监听")
    return e, q


def set_hp(e, php, pmax, qi, k0hp=2000, k0max=2000):
    e.g.mem.update({P_HP: php, P_MAX: pmax, P_QI: qi,
                    K_HP: k0hp, K_MAX: k0max})


def out_l2(e):
    """解出所有已发报文 -> [(fid, [字段...])]"""
    out = []
    for b in e.b.sent:
        try:
            p = sa.decode_layer1(b).split(b";")
        except Exception:
            continue
        fid = p[1].decode()
        vals = []
        for seg in p[2:-2]:
            try:
                vals.append(sa.deint(seg, KEY))
            except Exception:
                vals.append(None)
        out.append((fid, vals))
    return out


def sent_fids(e, fid):
    return [v for f, v in out_l2(e) if f == fid]


def schedule(e, reason="test"):
    """直接安排一次战后恢复（finish() 里走的就是这个入口）。"""
    e._schedule_post_battle_recovery(reason)
    wait_until(lambda: not e._recovery_pending, what="恢复流程结束")
    return e


def logs_of(e, q):
    """把队列里的 log 文本全取出来（队列里还有 stat/hook_state 等二元组）。"""
    out = []
    while True:
        try:
            item = q.get_nowait()
        except Exception:
            break
        if isinstance(item, tuple) and len(item) == 3 and item[0] == "log":
            out.append(str(item[2]))
    return out


# ===========================================================================
print("=" * 70)
print("战后自动恢复 v1 测试")
print("=" * 70)

# ---------------------------------------------------------------------------
# Step 2：checksum / builder（文档 §72 / §73）
# ---------------------------------------------------------------------------
# 用真实 target：0=角色、1=K0（原 target=4 实测 HP 不涨，已作废）
assert stw_engine._action_check(60, 54, 1, 0) == 115     # 精灵[1] 治角色
assert stw_engine._action_check(60, 54, 1, 1) == 116     # 精灵[1] 治 K0
assert stw_engine._action_check(60, 54, 7, 0) == 121     # 物品对自己
assert stw_engine._action_check(61, 54, 1, 0) == 116     # 换坐标必须跟着变
assert stw_engine._action_check(61, 54, 7, 0) == 122
l2 = stw_engine.build_use_spirit_l2(60, 54, 1, 0, KEY)
assert [sa.deint(x, KEY) for x in l2.split(b";")[2:-2]] == [60, 54, 1, 0, 115]
l2 = stw_engine.build_use_spirit_l2(60, 54, 1, 1, KEY)
assert [sa.deint(x, KEY) for x in l2.split(b";")[2:-2]] == [60, 54, 1, 1, 116]
l2 = stw_engine.build_use_item_l2(60, 54, 7, 0, KEY)
assert [sa.deint(x, KEY) for x in l2.split(b";")[2:-2]] == [60, 54, 7, 0, 121]
print("OK checksum 不写死：60/54/1/0=115 · 1/1=116 · 7/0=121 · 换坐标 61/54 -> 116/122")

# ---------------------------------------------------------------------------
# T01 角色满血 -> 什么都不发
# ---------------------------------------------------------------------------
e, q = start_engine()
set_hp(e, 2000, 2000, 50)
schedule(e)
assert not sent_fids(e, "57") and not sent_fids(e, "17"), out_l2(e)
assert e._recovery_state == "IDLE"
print("OK T01 满血：不发药、不放精灵")
stop(e)

# ---------------------------------------------------------------------------
# T02 / T03：缺 299 / 缺 300 都不治疗（必须 > 300）
# ---------------------------------------------------------------------------
for miss in (299, 300):
    e, q = start_engine()
    set_hp(e, 2000 - miss, 2000, 50)
    schedule(e)
    assert not sent_fids(e, "57"), f"缺{miss} 不该治疗：{out_l2(e)}"
    assert e._recovery_pending is False
    stop(e)
print("OK T02/T03 缺 299 / 缺 300 都不治疗（阈值是 > 300）")

# ---------------------------------------------------------------------------
# T04：缺 301 + 气力 31 -> 直接 fid=57，不发 fid=17
# ---------------------------------------------------------------------------
e, q = start_engine()
set_hp(e, 1699, 2000, 31)
e._schedule_post_battle_recovery("T04")
# 等进入 WAIT_HEAL（说明精灵已发出）再让 HP 上涨
wait_until(lambda: e._recovery_state == "WAIT_HEAL", what="精灵已发出")
assert not sent_fids(e, "17"), "气力 31 > 30，不该吃药"
sp = sent_fids(e, "57")
assert len(sp) == 1 and sp[0][2] == 1 and sp[0][3] == 0, sp
set_hp(e, 1900, 2000, 31)          # HP 真的涨了才算成功
wait_until(lambda: not e._recovery_pending, what="恢复完成")
# 每对象每场最多一次：HP 涨过之后回 CHECK，player 已 done，不会再补第二发
assert len(sent_fids(e, "57")) == 1, sent_fids(e, "57")
assert "治疗生效" in " ".join(logs_of(e, q))
print("OK T04 缺301 + 气力31：直接 fid=57（技能1 / 目标0=角色），HP 上涨后结束")
stop(e)

# ---------------------------------------------------------------------------
# T05：缺 301 + 气力 30，气力药在格 2
# ---------------------------------------------------------------------------
e, q = start_engine()
set_hp(e, 1699, 2000, 30)
e._schedule_post_battle_recovery("T05")
wait_until(lambda: e._recovery_state == "WAIT_QI", what="已发 fid=17")
it = sent_fids(e, "17")
assert len(it) == 1 and it[0][2] == 2 and it[0][3] == 0, it
set_hp(e, 1699, 2000, 65)          # 气力涨了
wait_until(lambda: e._recovery_state == "WAIT_HEAL", what="QI 生效后转治疗")
assert e._qi_known_slot == 2 and e._qi_scan_next_slot == 3
set_hp(e, 1900, 2000, 65)
wait_until(lambda: not e._recovery_pending, what="恢复完成")
assert len(sent_fids(e, "17")) == 1, "QI 一涨就停止扫描，不该再发第二格"
print("OK T05 气力药在格2：fid=17 slot2 -> QI 上涨 -> 停止扫描 -> fid=57")
stop(e)

# ---------------------------------------------------------------------------
# T06：气力药在格 8（2..7 全部无效），且 9..15 绝不再发
# ---------------------------------------------------------------------------
e, q = start_engine()
set_hp(e, 1699, 2000, 0)
e._schedule_post_battle_recovery("T06")
for expect in range(2, 9):
    wait_until(lambda n=expect: len(sent_fids(e, "17")) == n - 1,
               what=f"等第 {expect-1} 次 fid=17")
    # 只有格 8 会让气力上涨
    set_hp(e, 1699, 2000, 60 if expect == 8 else 0)
    wait_until(lambda: e._recovery_state in ("WAIT_HEAL", "CHECK")
               or len(sent_fids(e, "17")) == expect,
               what=f"格{expect} 判定完成")
slots = [v[2] for v in sent_fids(e, "17")]
assert slots == [2, 3, 4, 5, 6, 7, 8], slots
wait_until(lambda: not e._recovery_pending or e._recovery_state == "WAIT_HEAL",
           what="扫描结束/进入治疗")
assert e._qi_known_slot == 8 and e._qi_scan_next_slot == 9
assert 9 not in slots and 15 not in slots, "QI 一涨就停，9..15 不该再发"
print(f"OK T06 气力药在格8：依次尝试 {slots}，成功后停止（9..15 未发）")
stop(e)

# ---------------------------------------------------------------------------
# T07A：气力药在格 15（2..14 全部无效）
# ---------------------------------------------------------------------------
e, q = start_engine()
set_hp(e, 1699, 2000, 0)
e._schedule_post_battle_recovery("T07A")
for expect in range(2, 16):
    wait_until(lambda n=expect: len(sent_fids(e, "17")) == n - 1,
               what=f"等第 {expect-1} 次 fid=17")
    set_hp(e, 1699, 2000, 60 if expect == 15 else 0)
    wait_until(lambda: e._recovery_state in ("WAIT_HEAL", "CHECK")
               or len(sent_fids(e, "17")) == expect,
               what=f"格{expect} 判定完成")
slots = [v[2] for v in sent_fids(e, "17")]
assert slots == list(range(2, 16)), slots
assert e._qi_known_slot == 15 and e._qi_scan_next_slot == 16
print("OK T07A 气力药在格15：2..15 全部走完，最后一格生效后停止")
stop(e)

# ---------------------------------------------------------------------------
# T07：2..15 都没有气力药 -> 全局 break，Engine 主循环退出
# ---------------------------------------------------------------------------
e, q = start_engine()
set_hp(e, 1699, 2000, 0)
e._schedule_post_battle_recovery("T07")
wait_until(lambda: e._global_break or not e.is_alive(),
           timeout=25.0, what="全局 break")
wait_until(lambda: not e.is_alive(), timeout=10.0, what="Engine 线程结束")
slots = [v[2] for v in sent_fids(e, "17")]
assert slots == list(range(2, 16)), slots
assert not sent_fids(e, "57"), "没气力就不该放精灵"
assert e._global_break and e._global_break_reason
assert not e.is_alive(), "全局 break 后 Engine 线程必须结束"
print(f"OK T07 2..15 全无效：{len(slots)} 格各一次 -> 全局 break，Engine 线程结束")
print(f"      break 原因：{e._global_break_reason}")

# ---------------------------------------------------------------------------
# T07B：跨战斗全局游标（known 优先复用 / known 失效后从 next 继续 / 绝不回 2）
# ---------------------------------------------------------------------------
e, q = start_engine()
# —— 第 1 场：2、3 失败，4 成功
set_hp(e, 1699, 2000, 0)
e._schedule_post_battle_recovery("B1")
for expect in (2, 3, 4):
    wait_until(lambda n=expect: len(sent_fids(e, "17")) == n - 1,
               what=f"B1 等第 {expect-1} 次 fid=17")
    set_hp(e, 1699, 2000, 60 if expect == 4 else 0)
    wait_until(lambda: e._recovery_state in ("WAIT_HEAL", "CHECK")
               or len(sent_fids(e, "17")) == expect, what=f"B1 格{expect}")
wait_until(lambda: e._recovery_state == "WAIT_HEAL", what="B1 转治疗")
assert (e._qi_known_slot, e._qi_scan_next_slot) == (4, 5)
set_hp(e, 1900, 2000, 60)          # 治疗生效，本场结束
wait_until(lambda: not e._recovery_pending, what="B1 结束")

# —— 第 2 场：气力充足 -> 不扫描，全局状态保持
set_hp(e, 1699, 2000, 80)
n_before = len(sent_fids(e, "17"))
e._schedule_post_battle_recovery("B2")
wait_until(lambda: e._recovery_state == "WAIT_HEAL", what="B2 直接治疗")
assert len(sent_fids(e, "17")) == n_before, "气力够就不该扫背包"
assert (e._qi_known_slot, e._qi_scan_next_slot) == (4, 5)
set_hp(e, 1900, 2000, 80)
wait_until(lambda: not e._recovery_pending, what="B2 结束")

# —— 第 3 场：又缺气 -> 必须先试 known=4；4 失效后从 5 继续
set_hp(e, 1699, 2000, 10)
n_before = len(sent_fids(e, "17"))
e._schedule_post_battle_recovery("B3")
wait_until(lambda: len(sent_fids(e, "17")) == n_before + 1,
           what="B3 第一次 fid=17")
assert sent_fids(e, "17")[-1][2] == 4, "必须先复用 known=4"
# 格 4 不再生效 -> known 失效，从 5 继续
wait_until(lambda: len(sent_fids(e, "17")) == n_before + 2,
           what="B3 第二次 fid=17")
assert sent_fids(e, "17")[-1][2] == 5, "known 失效后必须从 5 继续，不能回 2"
assert e._qi_known_slot is None and e._qi_scan_next_slot >= 5
slots3 = [v[2] for v in sent_fids(e, "17")[n_before:]]
assert 2 not in slots3, f"第三场绝不能回退到格2：{slots3}"
print(f"OK T07B 跨场游标：B1 known=4/next=5 -> B2 不扫描 -> B3 先试4再续5（{slots3}）")
stop(e)

# ---------------------------------------------------------------------------
# T08 / T09：治疗成功确认 / 精灵不生效则本场停止（不重复放）
# ---------------------------------------------------------------------------
e, q = start_engine()
set_hp(e, 1500, 2000, 50)
e._schedule_post_battle_recovery("T09")
wait_until(lambda: e._recovery_state == "WAIT_HEAL", what="精灵已发")
assert len(sent_fids(e, "57")) == 1
wait_until(lambda: not e._recovery_pending, timeout=8.0, what="治疗超时中止")
assert len(sent_fids(e, "57")) == 1, "2s 内 HP 没上涨就停止，绝不重复放精灵"
assert e._recovery_state == "IDLE" and not e._recovery_pending
print("OK T09 精灵不生效：只发一次 fid=57，超时后本场中止（不无限重试）")
stop(e)

# ---------------------------------------------------------------------------
# T13：K0 target=1 已确认 -> 角色满血 / K0 缺血时，真的发一条 target=1 的 fid=57
# ---------------------------------------------------------------------------
assert stw_engine.HEAL_TARGET_K0 == 1, "K0 target 应为 1（宠物）"
assert stw_engine.HEAL_TARGET_PLAYER == 0, "角色 target 应为 0"
e, q = start_engine()
set_hp(e, 2000, 2000, 50, k0hp=1000, k0max=2000)     # 角色满血，K0 缺 1000
e._schedule_post_battle_recovery("T13")
wait_until(lambda: sent_fids(e, "57"), what="K0 精灵已发")
vals = sent_fids(e, "57")[-1]
# build_use_spirit_l2 的字段顺序：x | y | skill_slot | target | check
assert vals[2] == stw_engine.HEAL_SKILL_SLOT, f"技能槽应为 1：{vals}"
assert vals[3] == 1, f"K0 target 必须为 1：{vals}"
assert vals[4] == vals[0] + vals[1] + vals[2] + vals[3], f"校验和不对：{vals}"
txt = " ".join(logs_of(e, q))
assert "K0骑宠" in txt, txt[-400:]
print(f"OK T13 K0 治疗：发出 fid=57 target=1（{vals}）")
stop(e)

# T13B：角色治疗必须是 target=0（原 target=4 实测 HP 不涨，已作废）
# ---------------------------------------------------------------------------
e, q = start_engine()
set_hp(e, 1500, 2000, 50, k0hp=2000, k0max=2000)     # 只有角色缺血
e._schedule_post_battle_recovery("T13B")
wait_until(lambda: sent_fids(e, "57"), what="角色精灵已发")
vals = sent_fids(e, "57")[-1]
assert vals[3] == 0, f"角色 target 必须为 0：{vals}"
assert vals[4] == vals[0] + vals[1] + vals[2] + vals[3], f"校验和不对：{vals}"
print(f"OK T13B 角色治疗：发出 fid=57 target=0（{vals}）")
stop(e)

# ---------------------------------------------------------------------------
# T16 / T17：WAIT_MAP（state 不是 9 就不动）/ 超时安全失败
# ---------------------------------------------------------------------------
e, q = start_engine()
set_hp(e, 1500, 2000, 50)
e.g.state = 10                      # 还没真正回到地图
e._schedule_post_battle_recovery("T16")
time.sleep(0.3)
assert e._recovery_state == "WAIT_MAP", e._recovery_state
assert not sent_fids(e, "17") and not sent_fids(e, "57"), out_l2(e)
wait_until(lambda: not e._recovery_pending, timeout=8.0, what="WAIT_MAP 超时")
assert e._recovery_state == "IDLE"
print("OK T16/T17 未回到 state=9：不发任何包；超时后安全失败（不死循环）")
stop(e)

# ---------------------------------------------------------------------------
# T18：恢复途中用户点「停止自动战斗」-> 立即取消
# ---------------------------------------------------------------------------
e, q = start_engine()
set_hp(e, 1699, 2000, 30)
e._schedule_post_battle_recovery("T18")
wait_until(lambda: e._recovery_state == "WAIT_QI", what="已发 fid=17")
n = len(sent_fids(e, "17"))
e.auto_ev.clear()
wait_until(lambda: not e._recovery_pending, what="恢复被取消")
time.sleep(0.3)
assert len(sent_fids(e, "17")) == n, "取消后不许再发"
print("OK T18 恢复途中停止自动战斗：立即取消，不再发任何动作")
stop(e)

# ---------------------------------------------------------------------------
# T19：恢复期间绝不发 fid=1 遇敌走位（最关键的一条互斥）
# ---------------------------------------------------------------------------
e, q = start_engine(fast_enc=True)
set_hp(e, 1699, 2000, 30)
e._schedule_post_battle_recovery("T19")
wait_until(lambda: e._recovery_state == "WAIT_QI", what="已发 fid=17")
time.sleep(0.4)
assert not sent_fids(e, "1"), "恢复 pending 期间绝不能发遇敌包"
set_hp(e, 1699, 2000, 70)          # 气力涨了 -> 转治疗
wait_until(lambda: e._recovery_state == "WAIT_HEAL", what="转治疗")
assert not sent_fids(e, "1"), "恢复 pending 期间绝不能发遇敌包"
set_hp(e, 1950, 2000, 70)          # 治疗生效
wait_until(lambda: not e._recovery_pending, what="恢复完成")
wait_until(lambda: sent_fids(e, "1"), what="恢复完成后恢复遇敌")
print("OK T19 恢复期间 0 条 fid=1；恢复完成后遇敌自动恢复")
stop(e)

# ---------------------------------------------------------------------------
# §11：_clear_recovery() 绝不能重置全局扫描进度
# ---------------------------------------------------------------------------
e, q = start_engine()
e._qi_known_slot = 7
e._qi_scan_next_slot = 9
e._clear_recovery()
assert (e._qi_known_slot, e._qi_scan_next_slot) == (7, 9), "全局扫描进度被误清了"
e._schedule_post_battle_recovery("keep")
assert (e._qi_known_slot, e._qi_scan_next_slot) == (7, 9), "安排恢复也不许重置"
e._clear_recovery()
print("OK §11 全局扫描进度跨场次保留：clear / schedule 都不重置")
stop(e)

# ---------------------------------------------------------------------------
# §16：finish() 统一安排（走真实 BE 收尾路径，不在各分支复制）
# ---------------------------------------------------------------------------
e, q = start_engine(mode="attack")
set_hp(e, 1699, 2000, 50)
e.api.q.append(frame(7, "7|1|"))
e.api.q.append(frame(15, "BC|0|0|UV2D||18AD7|8C|4E1|5A9|5|1|巴朵兰恩|8C|40E|55A|"
                         "F|加宝格恩||18809|5A|2CA|2CA|1|0||0|0|0|"))
e.api.q.append(frame(15, "BA|18000|1|"))
wait_until(lambda: sent_fids(e, "14"), what="代发 fid=14")
e.api.q.append(frame(15, "BE|e0|f1|"))
wait_until(lambda: e._recovery_pending, timeout=10.0, what="BE 后安排恢复")
wait_until(lambda: e._recovery_state == "WAIT_HEAL", what="战后治疗已发出")
assert len(sent_fids(e, "57")) == 1
print("OK §16 真实 BE 收尾 -> finish() 统一安排恢复 -> fid=57 发出")
stop(e)

print()
print("=" * 70)
print("ALL POST-BATTLE RECOVERY TESTS PASSED")
print("=" * 70)
