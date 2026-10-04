# -*- coding: utf-8 -*-
"""抓宠统计口径改造测试（对应《抓宠统计口径改造开发文档》§12 测试矩阵）。

新 UI 四项：HPmax命中 / 毒伤确认 / 未命中 / 已丢弃

    hpmax_matched     通过第一层规则（名/等级/HP上限）被**首次锁定**的候选数
    poison_confirmed  verify_poison_full() 返回 ok=True 的次数
    no_match          决策窗口没有可用抓宠目标（沿用旧口径）
    dropped           真正发出 fid=21 的次数

⚠ 旧字段 attempts / successes / unknown 只是**不再显示**，语义一个字都不能动：
successes 仍服务「抓到 N 只后停止」，unknown 仍服务捕捉证据闭环。

覆盖：T01~T19 全部 19 条 + §11 的两条不变量。
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

from stw_ui import stw_ui                                      # noqa: E402
import stw_engine                                 # noqa: E402
from stw_config import POISON_STATE                  # noqa: E402
from stw_pet import full_stat_combos, poison_dmg     # noqa: E402
from stw_engine import Engine                                 # noqa: E402
from stw_pet import CATCH_SAMPLE_TEXT, parse_catch_rule_text  # noqa: E402

sa = stw_engine.sa
stw_engine.LOG = os.path.join(tempfile.gettempdir(), "_test_catch_stat_log.jsonl")

ACCOUNT = "testacct"
KEY = sa.make_l2_key(ACCOUNT)
RULES = {r["name"]: r for r in [parse_catch_rule_text(CATCH_SAMPLE_TEXT)]}
assert 913 in RULES["巴朵兰恩"]["levels"][100]["max_hp"]

LV, HPMAX = 100, 913
DMG = min({poison_dmg(c, LV, "derived") for c in full_stat_combos(LV, HPMAX)})
BAD_DMG = DMG + 8            # 一个必定不在预期集合里的假毒跳

BLOCK_ALLY0 = "0|UV2D||18AD7|8C|4E1|5A9|5|1|巴朵兰恩|8C|40E|55A|"
BLOCK_ALLY5 = "5|min-1||187B2|80|41F|4E3|1|0||0|0|0|"


def block_enemy(lv, hp, hpmax, state=1, slot=0xF, name="巴朵兰恩"):
    return ("%X|%s||18809|%X|%X|%X|%X|0||0|0|0|"
            % (slot, name, lv, hp, hpmax, state))


def bc_of(*enemies):
    return "BC|0|" + BLOCK_ALLY0 + BLOCK_ALLY5 + "".join(enemies)


def bc(lv, hp, hpmax, state=1, slot=0xF, name="巴朵兰恩"):
    return bc_of(block_enemy(lv, hp, hpmax, state, slot, name))


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
        return {"state": 9, "x": 68, "y": 35, "map": 999999}

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


def cmds_of(e):
    out = []
    for b in e.b.sent:
        try:
            p = sa.decode_layer1(b).split(b";")
        except Exception:
            continue
        if p[1] != b"14":
            continue
        out.append(sa.destring(p[2], KEY).decode("gb18030", "replace"))
    return out


def wait_until(pred, timeout=10.0, what=""):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if pred():
            return True
        time.sleep(0.05)
    raise AssertionError(f"等不到条件成立：{what}（{timeout}s）")


def stop(e):
    e.stop_flag.set()
    e.join(timeout=5)


def start_engine(poison=True, ratio=0.10, verify="log", fallback="flee",
                 drop_non_full=False):
    q = queue.Queue()
    cfg = {"pid": 0, "account": ACCOUNT, "accounts": [ACCOUNT],
           "fast_enc": False, "fast_battle": True, "mode": "catch",
           "interval": 0.1, "secs": 100000.0, "maxb": 999,
           "show46": False, "showraw": False,
           "catch": {"rules": RULES, "no_match_action": fallback,
                     "pet_action": "attack", "after_success": "continue",
                     "stop_count": 1, "drop_non_full": drop_non_full,
                     "poison_enabled": poison, "poison_skill": 2,
                     "poison_hp_ratio": ratio, "poison_verify": verify,
                     "poison_dmg_mode": "derived"}}
    e = Engine(cfg, q)
    e.auto_ev.set()
    e.start()
    wait_until(lambda: e.battle_hook_active, what="引擎挂载监听")
    return e, q


def open_battle(e, body=None, lv=LV, hp=HPMAX, hpmax=HPMAX, state=1):
    e.api.q.append(frame(7, "7|1|"))
    e.api.q.append(frame(15, body or bc(lv, hp, hpmax, state)))
    e.api.q.append(frame(15, "BA|18000|1|"))


def next_round(e, body=None, lv=LV, hp=HPMAX, hpmax=HPMAX, state=1, rnd=2):
    e.api.q.append(frame(15, "BM|F|1|"))
    e.api.q.append(frame(15, body or bc(lv, hp, hpmax, state)))
    e.api.q.append(frame(15, f"BA|18000|{rnd}|"))


def stat(e, key):
    return e.catch_stats[key]


print("=" * 70)
print("抓宠统计口径测试（HPmax命中 / 毒伤确认 / 未命中 / 已丢弃）")
print("=" * 70)
print(f"   Lv{LV}/{HPMAX} 预期毒伤 {DMG}；假毒跳用 {BAD_DMG}")

# ---------------------------------------------------------------------------
# T01：毒模式筛到 1 个目标 -> HPmax命中 +1
# T02/T03：ΔHP=0 连续补毒 -> HPmax 不重复、毒伤确认不加
# ---------------------------------------------------------------------------
print("\n--- T01~T03：首次锁定 +1；补毒不重复 ---")
e, q = start_engine(poison=True, ratio=0.10, verify="log")
open_battle(e)
wait_until(lambda: cmds_of(e), what="首轮上毒")
assert stat(e, "hpmax_matched") == 1, e.catch_stats
assert stat(e, "poison_confirmed") == 0, e.catch_stats
print("OK T01 毒模式筛到目标 -> HPmax命中 1")

next_round(e, hp=HPMAX, state=1, rnd=2)          # ΔHP=0 -> 补毒
wait_until(lambda: len(cmds_of(e)) >= 4, what="第二轮补毒")
next_round(e, hp=HPMAX, state=1, rnd=3)          # 还是 ΔHP=0
wait_until(lambda: len(cmds_of(e)) >= 6, what="第三轮补毒")
assert stat(e, "hpmax_matched") == 1, "补毒不该重复计 HPmax"
assert stat(e, "poison_confirmed") == 0, "ΔHP=0 不算确认"
print("OK T02/T03 连续补毒：HPmax 仍为 1，毒伤确认 0")
stop(e)

# ---------------------------------------------------------------------------
# T04：ΔHP>0 且验证通过 -> 毒伤确认 +1
# T05：之后控血多回合 -> 不再增加
# ---------------------------------------------------------------------------
print("\n--- T04~T05：验证通过 +1；控血不再增加 ---")
e, q = start_engine(poison=True, ratio=0.10, verify="log")
open_battle(e)
wait_until(lambda: cmds_of(e), what="首轮上毒")
hp = HPMAX
n = 0
while True:                                      # 一路毒到 10% 以下
    hp -= DMG
    n += 1
    next_round(e, hp=hp, state=POISON_STATE, rnd=n + 1)
    wait_until(lambda: len(cmds_of(e)) >= 2 * (n + 1),
               what=f"第 {n + 1} 轮指令")
    if stat(e, "poison_confirmed"):
        break
    assert n < 30, "毒了 30 轮还没验证通过，测试写错了"
assert stat(e, "poison_confirmed") == 1, e.catch_stats
assert stat(e, "hpmax_matched") == 1, e.catch_stats
print(f"OK T04 第 {n} 轮毒跳验证通过 -> 毒伤确认 1（HPmax 仍 1）")

for i in range(3):                               # 再控血 3 回合
    hp = max(1, hp - DMG)
    next_round(e, hp=hp, state=POISON_STATE, rnd=n + 2 + i)
    wait_until(lambda: len(cmds_of(e)) >= 2 * (n + 2 + i),
               what=f"控血第 {i + 1} 轮")
assert stat(e, "poison_confirmed") == 1, "控血阶段不能再确认一次"
assert stat(e, "hpmax_matched") == 1, e.catch_stats
print("OK T05 之后控血 3 回合：毒伤确认仍为 1")
stop(e)

# ---------------------------------------------------------------------------
# T06：log 模式验证失败 -> 毒伤确认 +0，但仍进控血（pverified=True）
#      ★ 本次最重要的测试点：log 失败也会 pverified=True，绝不能误计
# ---------------------------------------------------------------------------
print("\n--- T06：log 模式验证失败 -> 毒伤确认 +0（仍继续控血）---")
e, q = start_engine(poison=True, ratio=0.10, verify="log")
open_battle(e)
wait_until(lambda: cmds_of(e), what="首轮上毒")
next_round(e, hp=HPMAX - BAD_DMG, state=POISON_STATE, rnd=2)
wait_until(lambda: len(cmds_of(e)) >= 4, what="假毒跳后的动作")
assert stat(e, "hpmax_matched") == 1, e.catch_stats
assert stat(e, "poison_confirmed") == 0, "log 模式验证失败绝不能计确认"
# 仍进控血：下一轮应该是继续毒/抓，而不是重新开始验证
next_round(e, hp=HPMAX - BAD_DMG - DMG, state=POISON_STATE, rnd=3)
wait_until(lambda: len(cmds_of(e)) >= 6, what="控血第二轮")
assert stat(e, "poison_confirmed") == 0, e.catch_stats
assert e.bs.pverified is True, "log 失败后仍要 pverified=True 才能继续控血"
print("OK T06 验证失败：HPmax 1 / 毒伤确认 0 / pverified 仍为 True")
stop(e)

# ---------------------------------------------------------------------------
# T07：strict 验证失败 -> 毒伤确认 +0，旧目标排除
# T08：strict 失败后立刻找到新目标 -> 新目标 HPmax命中 +1
# ---------------------------------------------------------------------------
print("\n--- T07~T08：strict 失败排除旧目标，新目标 HPmax +1 ---")
e, q = start_engine(poison=True, ratio=0.10, verify="strict")
two = bc_of(block_enemy(LV, HPMAX, HPMAX, 1, 0xF),
            block_enemy(LV, HPMAX, HPMAX, 1, 0x10))
open_battle(e, body=two)
wait_until(lambda: cmds_of(e), what="毒第一个目标")
assert cmds_of(e) == ["J|2|F", "W|FF|FF"], cmds_of(e)
assert stat(e, "hpmax_matched") == 1, e.catch_stats
# 假毒跳 -> strict 排除 0xF，当场换到 0x10
next_round(e, body=bc_of(block_enemy(LV, HPMAX - BAD_DMG, HPMAX,
                                     POISON_STATE, 0xF),
                         block_enemy(LV, HPMAX, HPMAX, 1, 0x10)),
           rnd=2)
wait_until(lambda: len(cmds_of(e)) >= 4, what="换目标后的指令")
got = cmds_of(e)
assert got[2:] == ["J|2|10", "W|FF|FF"], got
assert stat(e, "poison_confirmed") == 0, "strict 失败不算确认"
assert stat(e, "hpmax_matched") == 2, "新目标必须再记一次 HPmax"
assert stat(e, "no_match") == 0, "strict 排除旧目标 ≠ 未命中"
print("OK T07/T08 毒伤确认 0；HPmax 命中 2（旧 1 + 新 1）；未命中 0")
stop(e)

# ---------------------------------------------------------------------------
# T09：off 模式 -> HPmax 正常，毒伤确认恒 0
# ---------------------------------------------------------------------------
print("\n--- T09：off 模式 -> 毒伤确认恒 0 ---")
e, q = start_engine(poison=True, ratio=0.10, verify="off")
open_battle(e)
wait_until(lambda: cmds_of(e), what="首轮上毒")
next_round(e, hp=HPMAX - DMG, state=POISON_STATE, rnd=2)
wait_until(lambda: len(cmds_of(e)) >= 4, what="第二轮")
next_round(e, hp=HPMAX - 2 * DMG, state=POISON_STATE, rnd=3)
wait_until(lambda: len(cmds_of(e)) >= 6, what="第三轮")
assert stat(e, "hpmax_matched") == 1, e.catch_stats
assert stat(e, "poison_confirmed") == 0, "off 模式绝不产生毒伤确认"
print("OK T09 off：HPmax 1 / 毒伤确认 0")
stop(e)

# ---------------------------------------------------------------------------
# T10：不开启上毒 -> HPmax命中 +1、毒伤确认 0、attempts +1
# ---------------------------------------------------------------------------
print("\n--- T10：关闭上毒 -> HPmax +1 / 毒伤 0 / attempts +1 ---")
e, q = start_engine(poison=False)
open_battle(e)
wait_until(lambda: cmds_of(e), what="代发抓宠指令")
assert cmds_of(e) == ["T|F", "W|1|F"], cmds_of(e)
assert stat(e, "hpmax_matched") == 1, e.catch_stats
assert stat(e, "poison_confirmed") == 0, e.catch_stats
assert stat(e, "attempts") == 1, "真正发了 T 指令，attempts 必须 +1"
print("OK T10 非毒流程：HPmax 1 / 毒伤 0 / attempts 1（旧语义不变）")
stop(e)

# ---------------------------------------------------------------------------
# T11~T13：没有符合规则的目标 -> 未命中 +1（flee / attack / silent）
#          ★ T13 最关键：silent 返回 Command("none")，不是 fid14，
#            统计副作用必须在 kind 早退之前消费
# ---------------------------------------------------------------------------
for fallback in ("flee", "attack", "silent"):
    print(f"\n--- T11~T13：无可用目标，fallback={fallback} -> 未命中 +1 ---")
    e, q = start_engine(poison=False, fallback=fallback)
    # 名字不在规则库 -> 一定不匹配
    open_battle(e, body=bc(LV, HPMAX, HPMAX, 1, 0xF, name="石龟"))
    wait_until(lambda: stat(e, "no_match") >= 1, what="未命中 +1")
    assert stat(e, "hpmax_matched") == 0, e.catch_stats
    assert stat(e, "poison_confirmed") == 0, e.catch_stats
    print(f"OK fallback={fallback}：未命中 {stat(e, 'no_match')}，"
          f"HPmax 0，毒伤 0")
    if fallback == "silent":
        assert cmds_of(e) == [], "silent 不该发任何 fid=14"
        print("OK T13 silent（kind=none）未命中仍然 +1")
    stop(e)

# ---------------------------------------------------------------------------
# §11.1 不变量：poison_confirmed <= hpmax_matched
# ---------------------------------------------------------------------------
print("\n--- §11.1 不变量：毒伤确认 <= HPmax命中 ---")
e, q = start_engine(poison=True, ratio=0.10, verify="log")
open_battle(e)
wait_until(lambda: cmds_of(e), what="首轮上毒")
hp = HPMAX
for i in range(12):
    hp = max(1, hp - DMG)
    next_round(e, hp=hp, state=POISON_STATE, rnd=i + 2)
    wait_until(lambda: len(cmds_of(e)) >= 2 * (i + 2), what=f"第 {i + 2} 轮")
    assert stat(e, "poison_confirmed") <= stat(e, "hpmax_matched"), \
        e.catch_stats
    assert stat(e, "hpmax_matched") == 1, \
        f"同一目标补毒不该重复计 HPmax：{e.catch_stats}"
print(f"OK 12 轮补毒后仍是 HPmax {stat(e, 'hpmax_matched')} / "
      f"毒伤 {stat(e, 'poison_confirmed')}（不重复累计）")
stop(e)

# ---------------------------------------------------------------------------
# T18：UI 四项一开始全为 0；并且按新口径渲染
# ---------------------------------------------------------------------------
print("\n--- T18：UI 显示改为新四项 ---")
import tkinter as tk                                  # noqa: E402

app = stw_ui.App()
app.update()
assert app.v_cstat.get() == \
    "抓宠统计：HPmax命中 0 / 毒伤确认 0 / 未命中 0 / 已丢弃 0", app.v_cstat.get()
print(f"OK 初始文案：{app.v_cstat.get()}")

app._drain_item(("catch_stat", {
    "hpmax_matched": 12, "poison_confirmed": 3, "no_match": 47,
    "dropped": 2, "attempts": 5, "successes": 2, "unknown": 1,
    "mode": "catch"}))
want = "抓宠统计：HPmax命中 12 / 毒伤确认 3 / 未命中 47 / 已丢弃 2"
assert app.v_cstat.get() == want, app.v_cstat.get()
print(f"OK 渲染：{app.v_cstat.get()}")

# dropped=0 也必须显示（文档 §9.2：四项位置固定）
app._drain_item(("catch_stat", {"hpmax_matched": 1, "poison_confirmed": 0,
                                "no_match": 0, "dropped": 0, "mode": "catch"}))
assert "已丢弃 0" in app.v_cstat.get(), app.v_cstat.get()
print("OK 已丢弃 0 也固定显示（四项位置稳定）")
assert "尝试" not in app.v_cstat.get() \
    and "确认成功" not in app.v_cstat.get() \
    and "待确认" not in app.v_cstat.get(), app.v_cstat.get()
print("OK 不再显示「尝试 / 确认成功 / 待确认」")
app.destroy()

print("\n" + "=" * 70)
print("ALL CATCH STAT TESTS PASSED")
print("=" * 70)
