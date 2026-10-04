"""抓宠前上毒（猛毒）端到端测试

对应《抓宠智能筛选逻辑开发文档_v2.md》+《动作说明文档.MD》§5。

不连游戏：把真实的 Engine 跑起来，frida / 网桥 / 内存快照换成假的，
喂一整场「抓宠」报文进去，看它到底发什么 fid=14。

    Unit 1  毒伤公式 / 满档反查：verify_poison_full 自洽
    Unit 2  规则库白名单里每一条 (等级, HP上限) 都能反推出满档四维组合
    Case P1 开上毒 -> 第一个操作窗口发 J|2|F + W|FF|FF（不是 T|F）
    Case P2 毒跳 Δhp 正确 + 血量到阈值 -> 发 T|F + W|FF|FF
    Case P3 毒跳 Δhp=0（猛毒没命中）-> 只补毒，绝不抓
    Case P4 strict 模式 Δhp 不符 -> 排除该目标，换下一个
    Case P5 关掉上毒 -> 回到老流程 T|F + W|1|F（回归保护）
    Case P6 技能格可配置（J|5|F），不是写死 2

硬约束：
    · 上毒回合战宠必须 W|FF|FF 待机（否则把目标打死就抓不到了）
    · 抓宠回合战宠同样 W|FF|FF（不是老的 W|1|{t}）
    · 判定只用 Δhp，state 只用于日志
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
from stw_config import POISON_STATE                  # noqa: E402
from stw_pet import (full_stat_combos, poison_dmg,   # noqa: E402
                     verify_poison_full)
from stw_engine import Engine                            # noqa: E402
from stw_pet import (CATCH_SAMPLE_TEXT,                  # noqa: E402
                     parse_catch_rule_text)

sa = stw_engine.sa
stw_engine.LOG = os.path.join(tempfile.gettempdir(), "_test_poison_log.jsonl")

ACCOUNT = "testacct"
KEY = sa.make_l2_key(ACCOUNT)

RULES = {r["name"]: r for r in
         [parse_catch_rule_text(CATCH_SAMPLE_TEXT)]}
assert "巴朵兰恩" in RULES, sorted(RULES)
# 命中条件之一：巴朵兰恩 Lv100 maxHP=913
assert 913 in RULES["巴朵兰恩"]["levels"][100]["max_hp"]

LV = 100
HPMAX = 913
DMG = None            # 由满档模型算出来的正确毒跳伤害，下面填

# ---------------------------------------------------------------------------
# BC 构造器：13 字段一个槽（slot|name|extra|uid|lv|hp|max_hp|state|
#                          has_mount|mname|mlv|mhp|mhpmax）
# ---------------------------------------------------------------------------
BLOCK_ALLY0 = "0|UV2D||18AD7|8C|4E1|5A9|5|1|巴朵兰恩|8C|40E|55A|"
BLOCK_ALLY5 = "5|min-1||187B2|80|41F|4E3|1|0||0|0|0|"


def block_enemy(lv, hp, hpmax, state=1, slot=0xF, name="巴朵兰恩"):
    return ("%X|%s||18809|%X|%X|%X|%X|0||0|0|0|"
            % (slot, name, lv, hp, hpmax, state))


def bc(lv, hp, hpmax, state=1, slot=0xF, name="巴朵兰恩"):
    return ("BC|0|" + BLOCK_ALLY0 + BLOCK_ALLY5
            + block_enemy(lv, hp, hpmax, state, slot, name))


# ---------------------------------------------------------------------------
# 假依赖：frida / 网桥 / 内存快照
# ---------------------------------------------------------------------------
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
    """解出所有代发的 fid=14 指令内容（J|2|F / W|FF|FF / T|F …）。"""
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


def logs_of(q):
    """把引擎吐到队列里的日志文本全部捞出来（判"有没有刷警告"用）。"""
    out = []
    while True:
        try:
            item = q.get_nowait()
        except Exception:
            break
        if item and item[0] == "log":
            out.append(str(item[2]))
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


def start_engine(poison=True, ratio=0.15, verify="log", dmg="derived",
                 skill=2):
    q = queue.Queue()
    cfg = {"pid": 0, "account": ACCOUNT, "accounts": [ACCOUNT],
           "fast_enc": False, "fast_battle": True, "mode": "catch",
           "interval": 0.1, "secs": 100000.0, "maxb": 999,
           "show46": False, "showraw": False,
           "catch": {"rules": RULES, "no_match_action": "flee",
                     "pet_action": "attack", "after_success": "continue",
                     "stop_count": 1, "drop_non_full": False,
                     "poison_enabled": poison, "poison_skill": skill,
                     "poison_hp_ratio": ratio, "poison_verify": verify,
                     "poison_dmg_mode": dmg}}
    e = Engine(cfg, q)
    e.auto_ev.set()
    e.start()
    wait_until(lambda: e.battle_hook_active, what="引擎挂载监听")
    return e, q


def open_battle(e, lv=LV, hp=HPMAX, hpmax=HPMAX, state=1):
    """遇敌 + 第一份队伍数据 + 第一个操作窗口。"""
    e.api.q.append(frame(7, "7|1|"))
    e.api.q.append(frame(15, bc(lv, hp, hpmax, state)))
    e.api.q.append(frame(15, "BA|18000|1|"))


def next_round(e, lv=LV, hp=HPMAX, hpmax=HPMAX, state=1, bm=True):
    """上毒/攻击之后的新一回合：BM 结算 -> BC 更新 -> 新操作窗口。"""
    if bm:
        e.api.q.append(frame(15, "BM|F|1|"))
    e.api.q.append(frame(15, bc(lv, hp, hpmax, state)))
    e.api.q.append(frame(15, "BA|18000|2|"))


print("=" * 70)
print("抓宠前上毒（猛毒）测试")
print("=" * 70)

# ---------------------------------------------------------------------------
# Unit 1：毒伤公式 / 满档反查
# ---------------------------------------------------------------------------
print("\n--- Unit 1：verify_poison_full 自洽 ---")
combos = full_stat_combos(LV, HPMAX)
assert combos, "Lv100/913 必须能反推出满档四维组合"
expect = {poison_dmg(c, LV, "derived") for c in combos}
DMG = min(expect)
print(f"   Lv{LV}/{HPMAX} 满档组合 {len(combos)} 种，"
      f"derived 毒伤预期 {sorted(expect)}")
assert verify_poison_full(LV, HPMAX, DMG, "derived") == (True, expect)
# 界外值从集合两端外侧取，别硬编码「DMG+1」：万一哪天一个 (等级,maxHP) 能
# 对应多个毒伤值（历史上出现过），min+1 就还在集合内，断言会假失败。
# 当前口径下满档四维和恒为 123，所以每级只有一个值（Lv100 = 125，与用户的
# 实测表一致）。
for d in expect:
    assert verify_poison_full(LV, HPMAX, d, "derived")[0] is True, d
assert verify_poison_full(LV, HPMAX, min(expect) - 1, "derived")[0] is False
assert verify_poison_full(LV, HPMAX, max(expect) + 1, "derived")[0] is False
assert verify_poison_full(LV, HPMAX, 125, "derived")[0] is True, "对照用户实测表 Lv100=125"
assert verify_poison_full(LV, HPMAX, 124, "derived")[0] is False
assert verify_poison_full(LV, HPMAX, 126, "derived")[0] is False
# 根本不可能是满档的 (等级,HP上限) -> 预期集合为空，一律判不通过
ok, exp = verify_poison_full(96, 808, 10, "derived")
assert ok is False and exp == set(), (ok, exp)
# base 口径：四维和恒为 25+39+22+27+10=123 -> (123-20)//4 = 25，常量无区分力
assert {poison_dmg(c, LV, "base") for c in combos} == {25}
assert verify_poison_full(LV, HPMAX, 25, "base")[0] is True
print(f"   derived 毒伤 = {DMG}（base 口径恒为 25，无区分力，故默认 derived）")
print("OK 毒伤公式与满档反查自洽")

# ---------------------------------------------------------------------------
# Unit 2：规则库白名单 vs 满档成长模型（两边必须是同一套成长模型）
# ---------------------------------------------------------------------------
print("\n--- Unit 2：规则库白名单全部能反推满档 ---")
rule = RULES["巴朵兰恩"]
n_entry = n_bad = 0
for lv, d in sorted((rule.get("levels") or {}).items()):
    for hpmax in (d.get("max_hp") or set()):
        n_entry += 1
        if not full_stat_combos(lv, hpmax):
            n_bad += 1
            print(f"   ✗ Lv{lv}/{hpmax} 反推不出满档组合")
assert n_entry > 0, "规则库没解析出条目"
assert n_bad == 0, f"{n_bad}/{n_entry} 条白名单与成长模型不一致"
print(f"OK {n_entry}/{n_entry} 条白名单都能反推出满档四维组合")

# ---------------------------------------------------------------------------
# Case P1：开上毒 -> 第一个窗口发 J|2|F + W|FF|FF
# ---------------------------------------------------------------------------
print("\n--- Case P1：开上毒，第一个操作窗口 ---")
e, q = start_engine(poison=True, ratio=0.15)
open_battle(e)
wait_until(lambda: cmds_of(e), what="代发上毒指令")
got = cmds_of(e)
print(f"   已发 fid=14：{got}")
assert got == ["J|2|F", "W|FF|FF"], got
assert not any(c.startswith("T|") for c in got), "上毒前不许抓"
print("OK 初筛命中 -> J|2|F（猛毒·技能格2）+ W|FF|FF（战宠待机）")
stop(e)

# ---------------------------------------------------------------------------
# Case P2：毒跳 Δhp 正确 + 血量到阈值 -> 抓 T|F + W|FF|FF
# ---------------------------------------------------------------------------
print("\n--- Case P2：毒跳验证通过 + 控血达标 -> 抓宠 ---")
# ratio=0.70：修正后的毒伤一跳只掉 ~13.6%，要连续控好几轮才够到阈值；
# 中间每一轮都必须是「续毒」（已验证后只看血量比例，不再看 Δhp），
# 达标那一轮才发 T|F —— 顺带把「控血循环」本身也验了。
e, q = start_engine(poison=True, ratio=0.70, verify="log")
open_battle(e)
wait_until(lambda: cmds_of(e), what="代发上毒指令")
hp, n = HPMAX, 0
while True:
    hp -= DMG
    n += 1
    assert hp > 0, (hp, DMG)
    print(f"   毒跳第 {n} 次：{hp + DMG} -> {hp}（{hp / HPMAX:.1%}"
          f"{'  < 70% 达标' if hp / HPMAX < 0.70 else '  未达标 -> 续毒'}）")
    # BM 结算 + 新 BC（state=8 表示中毒中）+ 新操作窗口
    next_round(e, hp=hp, state=POISON_STATE)
    wait_until(lambda: len(cmds_of(e)) >= 2 * (n + 1),
               what=f"第 {n + 1} 回合指令")
    got = cmds_of(e)
    if hp / HPMAX < 0.70:
        break
    assert got[-2:] == ["J|2|F", "W|FF|FF"], f"未达标必须续毒，不能去抓：{got}"
print(f"   已发 fid=14：{got}")
assert got[-2:] == ["T|F", "W|FF|FF"], got
print(f"OK Δhp={DMG} 命中 -> 四维验证通过 -> 控血 {n} 轮达标 -> T|F + W|FF|FF")
stop(e)

# ---------------------------------------------------------------------------
# Case P3：Δhp=0（猛毒没命中）-> 只补毒，绝不抓
# ---------------------------------------------------------------------------
print("\n--- Case P3：毒没生效（Δhp=0）-> 补毒，不抓 ---")
e, q = start_engine(poison=True, ratio=0.15)
open_battle(e)
wait_until(lambda: cmds_of(e), what="代发上毒指令")
next_round(e, hp=HPMAX, state=1)          # 血量没掉
wait_until(lambda: len(cmds_of(e)) >= 4, what="第二回合指令")
got = cmds_of(e)
print(f"   已发 fid=14：{got}")
assert got[2:] == ["J|2|F", "W|FF|FF"], got
assert not any(c.startswith("T|") for c in got), "毒都没生效不许抓"
print("OK Δhp=0 -> 再上毒一轮，绝不提前抓宠")
stop(e)

# ---------------------------------------------------------------------------
# Case P4：strict 模式 Δhp 不符 -> 排除该目标，换下一个
# ---------------------------------------------------------------------------
print("\n--- Case P4：strict 模式验证不通过 -> 排除目标 ---")
e, q = start_engine(poison=True, ratio=0.15, verify="strict")
# 两只都符合规则：F 和 10（10 才是真满档，F 是冒牌）
bc_two = ("BC|0|" + BLOCK_ALLY0 + BLOCK_ALLY5
          + block_enemy(LV, HPMAX, HPMAX, 1, 0xF)
          + block_enemy(LV, HPMAX, HPMAX, 1, 0x10))
e.api.q.append(frame(7, "7|1|"))
e.api.q.append(frame(15, bc_two))
e.api.q.append(frame(15, "BA|18000|1|"))
wait_until(lambda: cmds_of(e), what="代发上毒指令")
assert cmds_of(e) == ["J|2|F", "W|FF|FF"], cmds_of(e)
# F 掉血量明显不对 -> strict 排除 F
# ⚠ 不能只偏 1：预期集合是多值的（140/141），差 1 可能仍在集合内。
BAD_DMG = max(expect) + 8
e.api.q.append(frame(15, "BM|F|1|"))
e.api.q.append(frame(15, ("BC|0|" + BLOCK_ALLY0 + BLOCK_ALLY5
                          + block_enemy(LV, HPMAX - BAD_DMG, HPMAX,
                                        POISON_STATE, 0xF)
                          + block_enemy(LV, HPMAX, HPMAX, 1, 0x10))))
e.api.q.append(frame(15, "BA|18000|2|"))
wait_until(lambda: len(cmds_of(e)) >= 4, what="换目标后的指令")
got = cmds_of(e)
print(f"   已发 fid=14：{got}")
assert got[2:] == ["J|2|10", "W|FF|FF"], got
print("OK strict：Δhp 不符 -> 排除 0xF，改毒下一个目标 0x10")
stop(e)

# ---------------------------------------------------------------------------
# Case P5：关掉上毒 -> 回到老流程 T|F + W|1|F（回归保护）
# ---------------------------------------------------------------------------
print("\n--- Case P5：关掉上毒 -> 老流程回归 ---")
e, q = start_engine(poison=False)
open_battle(e)
wait_until(lambda: cmds_of(e), what="代发抓宠指令")
got = cmds_of(e)
print(f"   已发 fid=14：{got}")
assert got == ["T|F", "W|1|F"], got
assert not any(c.startswith("J|") for c in got), "没开上毒不许发 J"
print("OK 开关关闭：仍是 T|F + W|1|F，上毒逻辑完全不介入")
stop(e)

# ---------------------------------------------------------------------------
# Case P6：技能格可配置
# ---------------------------------------------------------------------------
print("\n--- Case P6：技能格可配置（不是写死 2）---")
e, q = start_engine(poison=True, ratio=0.15, skill=5)
open_battle(e)
wait_until(lambda: cmds_of(e), what="代发上毒指令")
got = cmds_of(e)
print(f"   已发 fid=14：{got}")
assert got == ["J|5|F", "W|FF|FF"], got
print("OK poison_skill=5 -> J|5|F（换号不用改代码）")
stop(e)

# ---------------------------------------------------------------------------
# Case P7：strict 下所有候选都被排除 -> 走「未命中」兜底（逃跑）
# ---------------------------------------------------------------------------
print("\n--- Case P7：全部排除 -> 未命中兜底（逃跑）---")
e, q = start_engine(poison=True, ratio=0.15, verify="strict")
e.api.q.append(frame(7, "7|1|"))
e.api.q.append(frame(15, ("BC|0|" + BLOCK_ALLY0 + BLOCK_ALLY5
                          + block_enemy(LV, HPMAX, HPMAX, 1, 0xF)
                          + block_enemy(LV, HPMAX, HPMAX, 1, 0x10))))
e.api.q.append(frame(15, "BA|18000|1|"))
wait_until(lambda: cmds_of(e), what="毒第一个目标")
assert cmds_of(e) == ["J|2|F", "W|FF|FF"], cmds_of(e)
# F 验证失败 -> 换 10
e.api.q.append(frame(15, "BM|F|1|"))
e.api.q.append(frame(15, ("BC|0|" + BLOCK_ALLY0 + BLOCK_ALLY5
                          + block_enemy(LV, HPMAX - BAD_DMG, HPMAX,
                                        POISON_STATE, 0xF)
                          + block_enemy(LV, HPMAX, HPMAX, 1, 0x10))))
e.api.q.append(frame(15, "BA|18000|2|"))
wait_until(lambda: len(cmds_of(e)) >= 4, what="毒第二个目标")
assert cmds_of(e)[2:] == ["J|2|10", "W|FF|FF"], cmds_of(e)
# 10 也验证失败 -> 没有候选了 -> 按 no_match_action=flee 逃跑
e.api.q.append(frame(15, "BM|10|1|"))
e.api.q.append(frame(15, ("BC|0|" + BLOCK_ALLY0 + BLOCK_ALLY5
                          + block_enemy(LV, HPMAX - BAD_DMG, HPMAX,
                                        POISON_STATE, 0xF)
                          + block_enemy(LV, HPMAX - BAD_DMG, HPMAX,
                                        POISON_STATE, 0x10))))
e.api.q.append(frame(15, "BA|18000|3|"))
wait_until(lambda: len(cmds_of(e)) >= 6, what="未命中兜底指令")
got = cmds_of(e)
print(f"   已发 fid=14：{got}")
assert got[4:] == ["E", "W|FF|FF"], got
print("OK 候选全部排除后按设置逃跑，不会空着窗口把回合卡死")
stop(e)

# ---------------------------------------------------------------------------
# Case P8：verify=off -> 不判满档，只控血
# ---------------------------------------------------------------------------
print("\n--- Case P8：verify=off -> 只控血不验证 ---")
e, q = start_engine(poison=True, ratio=0.70, verify="off")
open_battle(e)
wait_until(lambda: cmds_of(e), what="代发上毒指令")
# Δhp 故意给错（413 ≠ 满档毒伤 320）：off 模式下不排除，
# 血量 500/913=54.8% < 70% 照样抓
assert (HPMAX - 500) != DMG
next_round(e, hp=500, state=POISON_STATE)
wait_until(lambda: len(cmds_of(e)) >= 4, what="第二回合指令")
got = cmds_of(e)
print(f"   已发 fid=14：{got}")
assert got[2:] == ["T|F", "W|FF|FF"], got
print("OK off 模式：Δhp 不参与判定，血量达标就抓")
stop(e)

# ---------------------------------------------------------------------------
# Case P9：配置项是脏数据也不能崩（回退默认值）
# ---------------------------------------------------------------------------
print("\n--- Case P9：脏配置回退默认值 ---")
e, q = start_engine(poison=True, ratio="abc", verify="bogus", dmg="bogus",
                    skill="x")
open_battle(e)
wait_until(lambda: cmds_of(e), what="代发上毒指令")
got = cmds_of(e)
print(f"   已发 fid=14：{got}")
assert got == ["J|2|F", "W|FF|FF"], got
print("OK ratio/verify/dmg/skill 全是脏值 -> 回退 0.10 / log / derived / 2")
stop(e)

# ---------------------------------------------------------------------------
# Case P10：界面开关 —— 上毒配置写进 cfg["catch"]
# ---------------------------------------------------------------------------
print("\n--- Case P10：界面开关 ---")
import tkinter as tk                                # noqa: E402

app = stw_ui.App()
app.update()
for attr in ("v_poison", "v_pskill", "v_pratio", "v_pverify", "v_pdmg"):
    assert hasattr(app, attr), f"抓宠面板缺少上毒控件 {attr}"
assert app.v_poison.get() is False, "上毒默认关闭"
assert app.v_pskill.get() == "2" and app.v_pratio.get() == "0.10"
assert app.v_pverify.get() == "log" and app.v_pdmg.get() == "derived"
app.v_poison.set(True)
app.v_pskill.set("4")
app.v_pratio.set("0.25")
app.v_pverify.set("strict")
app.v_pdmg.set("base")
app._sync()
c = app.cfg["catch"]
assert c["poison_enabled"] is True and c["poison_skill"] == 4
assert c["poison_hp_ratio"] == 0.25, c["poison_hp_ratio"]
assert c["poison_verify"] == "strict" and c["poison_dmg_mode"] == "base"
# 脏输入回退，不让引擎崩
app.v_pratio.set("abc")
app.v_pskill.set("x")
app._sync()
assert app.cfg["catch"]["poison_hp_ratio"] == 0.10
assert app.cfg["catch"]["poison_skill"] == 2
print("OK 界面：上毒开关/技能格/阈值/验证口径 同步进 cfg，脏输入回退默认")
app.destroy()

# ===========================================================================
# v2.2 修正补完：验证阶段 / 控血阶段必须分开（HP=1 是猛毒的正常边界）
# ===========================================================================
print("\n" + "=" * 70)
print("v2.2 §9 测试：两阶段分流")
print("=" * 70)

# ---------------------------------------------------------------------------
# v2.2 Case 1：未验证 + Δhp=0 + HP>10% -> 继续毒（不抓）
# ---------------------------------------------------------------------------
print("\n--- v2.2 C1：未验证 Δhp=0，HP>10% -> 继续毒 ---")
e, q = start_engine(poison=True, ratio=0.10)
open_battle(e, hp=HPMAX)
wait_until(lambda: cmds_of(e), what="首轮上毒")
# 连着两轮都毒不中，血量一直满 -> 只该补毒，绝不该抓
next_round(e, hp=HPMAX, state=1)
wait_until(lambda: len(cmds_of(e)) >= 4, what="第二轮指令")
next_round(e, hp=HPMAX, state=1)
wait_until(lambda: len(cmds_of(e)) >= 6, what="第三轮指令")
got = cmds_of(e)
print(f"   已发 fid=14：{got}")
assert all(c in ("J|2|F", "W|FF|FF") for c in got), got
assert not any(c.startswith("T|") for c in got), "没验证过不许抓"
print("OK Δhp=0 + HP 满 -> 只补毒，绝不提前抓宠")
stop(e)

# ---------------------------------------------------------------------------
# v2.2 Case 2：Δhp 符合满档 -> 进 POISON_CONTROL；HP 仍 >10% -> 续毒
# ---------------------------------------------------------------------------
print("\n--- v2.2 C2：验证通过但 HP 仍 >10% -> 续毒 ---")
e, q = start_engine(poison=True, ratio=0.10)
open_battle(e, hp=HPMAX)
wait_until(lambda: cmds_of(e), what="首轮上毒")
next_round(e, hp=HPMAX - DMG, state=POISON_STATE)
wait_until(lambda: len(cmds_of(e)) >= 4, what="第二轮指令")
got = cmds_of(e)
print(f"   已发 fid=14：{got}")
assert got[2:] == ["J|2|F", "W|FF|FF"], got
assert not any(c.startswith("T|") for c in got), "血还厚，不能抓"
print(f"OK Δhp={DMG} 命中 -> 进入控血阶段；{HPMAX - DMG}/{HPMAX} 仍 >10% -> 续毒")
stop(e)

# ---------------------------------------------------------------------------
# v2.2 Case 3：已验证后 HP=1 / Δhp=0 -> 不再补毒，直接抓宠（★核心回归）
# ---------------------------------------------------------------------------
print("\n--- v2.2 C3：已验证 + HP=1 -> 直接抓宠（不补毒）---")
e, q = start_engine(poison=True, ratio=0.10)
open_battle(e, hp=HPMAX)
wait_until(lambda: cmds_of(e), what="首轮上毒")
# 毒跳生效 -> 验证通过 -> 进控血；65% 还太厚 -> 续毒
next_round(e, hp=HPMAX - DMG, state=POISON_STATE)
wait_until(lambda: len(cmds_of(e)) >= 4, what="续毒")
assert cmds_of(e)[2:] == ["J|2|F", "W|FF|FF"], cmds_of(e)
# 血量被打到猛毒下限 HP=1：**已验证，不再看 Δhp**，直接抓
next_round(e, hp=1, state=POISON_STATE)
wait_until(lambda: len(cmds_of(e)) >= 6, what="HP=1 时的动作")
got = cmds_of(e)
print(f"   已发 fid=14：{got}")
assert got[4:] == ["T|F", "W|FF|FF"], got
# 抓失败后血量还是 1（Δhp=0），下一轮必须**再抓**，不能退回补毒
e.api.q.append(frame(15, "BT|a0|rF|f0|"))       # 本次没抓到
next_round(e, hp=1, state=POISON_STATE)
wait_until(lambda: len(cmds_of(e)) >= 8, what="抓失败后再来一轮")
got = cmds_of(e)
print(f"   已发 fid=14：{got}")
assert got[6:] == ["T|F", "W|FF|FF"], got
# 关键：控血阶段**不再跑满档验证**。旧实现续毒后会把 psm 拨回 WAIT_POISON，
# 于是 HP=1 那轮的 Δhp=592 又被拿去验一次，刷一条假的"四维验证不通过"。
bad = [t for t in logs_of(q) if "四维验证不通过" in t]
assert not bad, f"已进入控血阶段还在做满档验证：{bad}"
print("OK 已验证后 HP=1 / Δhp=0 一律抓宠，不会退化成补毒死循环")
print("OK 控血阶段不再重跑四维验证（没有假的『验证不通过』告警）")
stop(e)

# ---------------------------------------------------------------------------
# v2.2 Case 4：未验证 + HP=1 -> 继续验证，禁止抓宠
# ---------------------------------------------------------------------------
print("\n--- v2.2 C4：未验证 + HP=1 -> 禁止抓宠 ---")
e, q = start_engine(poison=True, ratio=0.10)
open_battle(e, hp=1)                            # 一上来就是猛毒下限
wait_until(lambda: cmds_of(e), what="首轮上毒")
assert cmds_of(e) == ["J|2|F", "W|FF|FF"], cmds_of(e)
# 第二轮：还是 1，Δhp=0 -> 再补一次
next_round(e, hp=1, state=1)
wait_until(lambda: len(cmds_of(e)) >= 4, what="第二轮指令")
assert cmds_of(e)[2:] == ["J|2|F", "W|FF|FF"], cmds_of(e)
# 第三轮：连续两次确认 HP=1 死角 -> 永远拿不到 Δhp，排除（避免文档 §1 的死循环）
next_round(e, hp=1, state=1)
wait_until(lambda: len(cmds_of(e)) >= 6, what="死角排除")
got = cmds_of(e)
print(f"   已发 fid=14：{got}")
assert not any(c.startswith("T|") for c in got), "没验证过严禁抓宠"
assert got[4:] == ["E", "W|FF|FF"], got
print("OK 未验证 + HP=1：只补毒/排除，绝不抓宠；且不会无限空转（按未命中兜底逃跑）")
stop(e)

# ---------------------------------------------------------------------------
# v2.2 附加：已验证后，BC state 不是 8 也不能挡住抓宠
# ---------------------------------------------------------------------------
print("\n--- v2.2 附加：控血阶段不看 state，血量达标就抓 ---")
# ratio 取 0.90：修正公式后一跳只掉到 789/913=86.4%，一步就能跨过阈值，
# 这样本用例只测「state!=8 不该挡住抓宠」，不掺进多轮控血的逻辑。
e, q = start_engine(poison=True, ratio=0.90)
open_battle(e, hp=HPMAX)
wait_until(lambda: cmds_of(e), what="首轮上毒")
# 毒跳生效（验证通过），但这一帧 BC 的 state 是普通值 1 而不是 8
next_round(e, hp=HPMAX - DMG, state=1)
wait_until(lambda: len(cmds_of(e)) >= 4, what="第二轮指令")
got = cmds_of(e)
print(f"   已发 fid=14：{got}")
assert got[2:] == ["T|F", "W|FF|FF"], got
print(f"OK 控血阶段只认 hp/hpmax（{HPMAX - DMG}/{HPMAX}="
      f"{(HPMAX - DMG) / HPMAX:.1%} < 90%），state!=8 不会把「该抓」误判成「补毒」")
stop(e)

print("\n" + "=" * 70)
print("ALL POISON TESTS PASSED")
print("=" * 70)
