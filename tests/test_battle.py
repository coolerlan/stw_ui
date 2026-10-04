# -*- coding: utf-8 -*-
"""v2.2 §12 test_battle.py：BattleSession 覆盖。

覆盖清单（§12）：
    一次BA一个动作 / fid14双指令 / 毒失败重试 / 毒成功验证 /
    pverified切换 / HP=1直接抓 / 非满档排除

纯函数测试：不起进程、不连游戏、不发真包 —— Battle 只产出 Command，
「怎么发送」由 Engine 负责（v2.2 §9），所以这里只断言决策结果。
"""
import os
import sys

# 仓库根 + stw_ui 包目录进 sys.path（从 __file__ 推，不写死绝对路径）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "stw_ui"))
sys.path.insert(0, _ROOT)

from stw_battle import BattleSession  # noqa: E402
from stw_pet import (CATCH_SAMPLE_TEXT, full_stat_combos,  # noqa: E402
                     parse_catch_rule_text, poison_dmg)

LV, HPMAX = 100, 913          # 与 _test_poison 同一套基准：Lv100/913 可反推满档
_rule = parse_catch_rule_text(CATCH_SAMPLE_TEXT)
RULES = {_rule["name"]: _rule}
_combos = full_stat_combos(LV, HPMAX)
assert _combos, "Lv100/913 必须能反推出满档四维组合"
DMG = min({poison_dmg(c, LV, "derived") for c in _combos})  # 成长四维口径
assert DMG > 0


def enemy(slot, hp, hpmax=HPMAX, lv=LV, name="巴朵兰恩", state=1):
    """造一个 BC 单位（敌方槽 0xF~0x18）。"""
    return {"slot": slot, "name": name, "lv": lv, "hp": hp,
            "hpmax": hpmax, "state": state, "mount": None}


def mk(units, **catch_kw):
    """造一个「已遇敌 + 已收到第一份队伍数据」的 BattleSession。"""
    cfg = {"mode": "catch"}
    c = {"rules": RULES, "no_match_action": "flee", "pet_action": "attack",
         "poison_enabled": True, "poison_skill": 2, "poison_hp_ratio": 0.15,
         "poison_verify": "log", "poison_dmg_mode": "derived"}
    c.update(catch_kw)
    logs = []
    bs = BattleSession(cfg, c,
                       log=lambda kind, text: logs.append((kind, text)))
    bs.reset_battle()                       # fid=7
    bs.on_bc(units, in_battle=True)         # 第一份 BC
    return bs, logs


def next_window(bs, units):
    """服务器只回 BM 结算 + 新 BC + 新的 BA low=0 窗口。"""
    bs.on_bh()
    bs.on_bc(units, in_battle=True)


# ---- Case A：一次 BA 一个动作 / fid14 双指令 ----
print("--- Case A：一次 BA 一个动作 / fid14 双指令 ---")
bs, logs = mk([enemy(0xF, HPMAX)])
cmd = bs.decide_action(rnd=1, rounds=0)
assert cmd.kind == "fid14" and cmd.mode == "poison", cmd
assert len(cmd.lines) == 2, cmd.lines        # 一次机会 = 角色 + 战宠两条
assert cmd.lines == ["J|2|F", "W|FF|FF"], cmd.lines
bs.mark_sent(cmd)                            # Engine 发完才推进状态
again = bs.decide_action(rnd=1, rounds=1)    # 同一窗口再来一次
assert again.kind == "none", again           # 本轮已提交未结算 -> 什么都不发
print("OK：一个窗口只出一个 Command；fid14 恒两条（角色+战宠）")

# ---- Case B：毒失败重试 ----
print("--- Case B：毒失败重试（Δhp=0 -> 补毒，绝不抓）---")
bs, logs = mk([enemy(0xF, HPMAX)])
cmd = bs.decide_action(rnd=1, rounds=0)
bs.mark_sent(cmd)
assert cmd.set_psm == "WAIT_POISON" and bs.psm == "WAIT_POISON"
next_window(bs, [enemy(0xF, HPMAX)])         # BM 到了但血没掉 -> Δhp=0
cmd2 = bs.decide_action(rnd=2, rounds=1)
assert cmd2.kind == "fid14" and cmd2.mode == "poison", cmd2
assert cmd2.lines == ["J|2|F", "W|FF|FF"], cmd2
assert bs.pv_tries == 1 and not bs.pverified
assert not any(c.startswith("T|") for c in cmd2.lines), "Δhp=0 时绝不抓"
bs.mark_sent(cmd2)
next_window(bs, [enemy(0xF, HPMAX)])
cmd3 = bs.decide_action(rnd=3, rounds=2)
assert bs.pv_tries == 2 and cmd3.mode == "poison"
assert not any(c.startswith("T|") for c in cmd3.lines)
print("OK：猛毒没命中只补毒（25~30% 命中率不算失败），连续两次也不抓")

# ---- Case C：毒成功验证 ----
print("--- Case C：毒成功验证（Δhp 命中 -> 四维验证 -> 进控血 -> 抓）---")
# ratio 取 0.90：修正后的毒伤一跳只掉 ~13.6%（913→789=86.4%），
# 单跳就够到 90% 阈值；取 0.70 的话这里期望只能是「续毒」。
bs, logs = mk([enemy(0xF, HPMAX)], poison_hp_ratio=0.90)
cmd = bs.decide_action(rnd=1, rounds=0)
bs.mark_sent(cmd)
after = HPMAX - DMG
next_window(bs, [enemy(0xF, after)])
cmd2 = bs.decide_action(rnd=2, rounds=1)
assert bs.pverified is True, f"Δhp={DMG} 应命中满档预期"
assert cmd2.mode == "catch" and cmd2.lines == ["T|F", "W|FF|FF"], cmd2
assert cmd2.attempt is True and cmd2.name == "巴朵兰恩"
assert cmd2.set_psm == "CATCH"
print(f"OK：Δhp={DMG} 验证通过 -> 控血 {after}/{HPMAX}="
      f"{after / HPMAX:.1%} < 90% -> T|F + W|FF|FF")

# ---- Case C2：pverified 切换（两阶段判据不同）----
print("--- Case C2：pverified 切换（验证前看 Δhp，验证后只看血量比例）---")
# 验证前：血量已经很低（5.5%）但 Δhp=0 —— 只补毒，绝不抓
bs, logs = mk([enemy(0xF, 50)], poison_hp_ratio=0.70)
cmd = bs.decide_action(rnd=1, rounds=0)     # begin() 记 php_before=50
bs.mark_sent(cmd)
next_window(bs, [enemy(0xF, 50)])           # Δhp=0
cmd2 = bs.decide_action(rnd=2, rounds=1)
assert bs.pverified is False
assert cmd2.mode == "poison", "未验证：血量再低也只看 Δhp，绝不抓"
# 验证后：不再回头判 Δhp，只看血量比例；且停在 POISON_CONTROL 不回 WAIT_POISON
bs, logs = mk([enemy(0xF, HPMAX)], poison_hp_ratio=0.15)
c1 = bs.decide_action(rnd=1, rounds=0)
bs.mark_sent(c1)
next_window(bs, [enemy(0xF, HPMAX - DMG)])
c2 = bs.decide_action(rnd=2, rounds=1)      # 65% > 15% -> 续毒
assert bs.pverified is True and c2.mode == "poison", c2
assert c2.set_psm == "POISON_CONTROL", "控血阶段不许回到 WAIT_POISON"
print("OK：验证前只看 Δhp（血量 5.5% 也不抓）；验证后只看比例且停控血")

# ---- Case D：HP=1（猛毒下限）----
print("--- Case D：HP=1（猛毒最低保留 1）---")
# D1 未验证 + HP=1：永远拿不到 Δhp -> 排除，交给兜底
bs, logs = mk([enemy(0xF, 1)])
cmd = bs.decide_action(rnd=1, rounds=0)     # hp=1>0，初筛仍会命中并上毒
bs.mark_sent(cmd)
next_window(bs, [enemy(0xF, 1)])            # Δhp=0, pv_tries=1
cmd2 = bs.decide_action(rnd=2, rounds=1)
bs.mark_sent(cmd2)
next_window(bs, [enemy(0xF, 1)])            # Δhp=0, pv_tries=2 + HP=1 -> 排除
cmd3 = bs.decide_action(rnd=3, rounds=2)
assert bs.pverified is False
assert 0xF in bs.pexcluded, bs.pexcluded
assert cmd3.mode == "flee" and cmd3.no_match is True, cmd3  # 没目标 -> 兜底逃跑
print("OK：未验证 + HP=1 -> 无法做满档验证 -> 排除（绝不硬抓）")

# D2 已验证 + HP=1：Δhp 不再参与判断 -> 直接抓
bs, logs = mk([enemy(0xF, HPMAX)], poison_hp_ratio=0.15)
c1 = bs.decide_action(rnd=1, rounds=0)
bs.mark_sent(c1)
next_window(bs, [enemy(0xF, HPMAX - DMG)])
c2 = bs.decide_action(rnd=2, rounds=1)      # 验证通过 -> 续毒
assert bs.pverified is True and c2.mode == "poison"
bs.mark_sent(c2)
next_window(bs, [enemy(0xF, 1)])            # 毒到 HP=1（猛毒下限，Δhp 属正常）
c3 = bs.decide_action(rnd=3, rounds=2)
assert c3.mode == "catch" and c3.lines == ["T|F", "W|FF|FF"], c3
print("OK：已验证 + HP=1 -> 不看 Δhp，直接抓（HP=1 是猛毒正常边界）")

# ---- Case E：非满档排除（strict）----
print("--- Case E：非满档排除（strict）---")
bs, logs = mk([enemy(0xF, HPMAX), enemy(0x10, HPMAX)], poison_verify="strict")
cmd = bs.decide_action(rnd=1, rounds=0)
assert cmd.target == 0xF, cmd
bs.mark_sent(cmd)
# Δhp 差 1 点 -> 四维验证不通过 -> strict 排除，并当场换下一只（不能停手）
next_window(bs, [enemy(0xF, HPMAX - (DMG - 1)), enemy(0x10, HPMAX)])
cmd2 = bs.decide_action(rnd=2, rounds=1)
assert 0xF in bs.pexcluded, bs.pexcluded
assert cmd2.kind == "fid14" and cmd2.target == 0x10, cmd2
assert cmd2.lines == ["J|2|10", "W|FF|FF"], cmd2
print("OK：验证不通过(strict) -> 排除该目标并当场换下一只（操作窗口不能空过）")

print()
print("RESULT: PASS —— test_battle 全部通过")
