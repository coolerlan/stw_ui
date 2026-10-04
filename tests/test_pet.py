# -*- coding: utf-8 -*-
"""§16 test_pet.py：stw_pet 覆盖。

覆盖清单（v2.1 §16）：
    K长包 / K短包 / 空K槽 / 满档 / 非满档 /
    毒伤验证 / 规则匹配 / build_drop_l2
纯函数测试：不起进程、不连游戏、不碰 Tk。
"""
import os
import sys

# 仓库根 + stw_ui 包目录进 sys.path（从 __file__ 推，不写死绝对路径）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "stw_ui"))
sys.path.insert(0, _ROOT)

from stw_pet import (CATCH_SAMPLE_TEXT, build_drop_l2,  # noqa: E402
                     full_stat_combos, grow_stats, is_full_pet,
                     match_catch_rule, parse_catch_rule_text, parse_k_name,
                     parse_k_pet, poison_dmg, verify_poison_full)

# ---- K 长包 ----
print("--- K 长包 ---")
long_pkt = ("K3|1|100373|1209|1306|0|0|18153|-1|140|327|215|190|100|"
            "0|0|0|0|0|0|石龟|min-1|")
d = parse_k_pet(long_pkt)
assert d is not None
assert d["slot"] == "K3" and d["level"] == 140 and d["pet_id"] == 100373
assert (d["hp"], d["hp_max"]) == (1209, 1306)
assert (d["atk"], d["def"], d["agi"], d["loyalty"]) == (327, 215, 190, 100)
assert d["base_name"] == "石龟" and d["title"] == "min-1"
assert d["name"] == "石龟 min-1"            # 显示名带称号
assert d["partial"] is False
# 称号位是纯数值串时不拼进显示名
d2 = parse_k_pet(long_pkt.replace("min-1|", "56.13.10.6|"))
assert d2["title"] == "56.13.10.6" and d2["name"] == "石龟"
# 等级 0 的长包当无效
assert parse_k_pet(long_pkt.replace("|140|", "|0|", 1)) is None
print("OK：字段表 / 显示名 / 等级 0 拒绝")

# ---- K 短包 ----
print("--- K 短包 ---")
short_pkt = "K3|xZa|1256|0|18153|327|215|190|100|0|20|80|0|"
d = parse_k_pet(short_pkt)
assert d is not None
assert d["slot"] == "K3" and d["partial"] is True
assert d["level"] is None and d["name"] is None and d["base_name"] is None
assert (d["hp"], d["atk"], d["def"], d["agi"]) == (1256, 327, 215, 190)
assert d["loyalty"] == 100 and d["hp_max"] == 0 and d["pet_id"] is None
print("OK：短包只有数值覆盖（无等级/无名字）")

# ---- 空 K 槽 / 非法包 ----
print("--- 空 K 槽 / 非法包 ---")
assert parse_k_pet("K2|0|") is None               # 空槽
assert parse_k_pet("") is None
assert parse_k_pet("ZZ|1|2|3|4|5|6|7|8|9") is None  # 非 K 槽
assert parse_k_pet("K9|1|2|3|4|5|6|7|8|9") is None  # 槽位越界
assert parse_k_name("K0|1|100274|1042|1251|0|0|10") is None  # 纯数值尾巴
assert parse_k_name("K1|xx|贝恩达斯") == "贝恩达斯"
print("OK：空槽/非法一律 None")

# ---- 满档 / 非满档 ----
print("--- 满档 / 非满档 ---")
# 独立构造已知满档样本：base(25,39,22,27) + 10 点全加敏 (0,0,0,10)
# ⚠ 成长公式只走 grow_stats（攻/防带交叉项，不是 K*S//100）；
#   等级不用 Lv1 —— K=27 时面板数值大量撞车，严格判定恒 False。
LV = 20
V, S, T, D = 25, 39, 22, 27 + 10
hp, atk, dfn, agi = grow_stats(LV, V, S, T, D)
assert is_full_pet(LV, hp, atk, dfn, agi) is True       # 满档
assert is_full_pet(LV, hp, atk, dfn, agi + 1) is False  # 敏偏 1 -> 非满档
assert is_full_pet(LV, hp + 100, atk, dfn, agi) is False  # HP 上界外
assert is_full_pet(0, hp, atk, dfn, agi) is False       # 等级 < 1
assert is_full_pet(LV, "x", atk, dfn, agi) is False     # 非数值
# 真实样本回归：用户实机抓到的 Lv104/HP882 攻204 防141 敏144 是满档。
# 这条同时钉死「简化口径 K*S//100 已作废」——它只能算出攻 171。
assert is_full_pet(104, 882, 204, 141, 144) is True
print(f"OK：满档判定 / 非满档拒绝（Lv{LV} 样本 {hp}/{atk}/{dfn}/{agi}"
      " + 真实样本 Lv104）")

# ---- 毒伤验证 ----
print("--- 毒伤验证 ---")
combos = full_stat_combos(LV, hp)
assert combos, "满档样本必须能反查出组合"
assert (hp, atk, dfn, agi, (V, S, T, D)) in combos, "构造样本必须与反查同源"
delta_known = poison_dmg((hp, atk, dfn, agi, (V, S, T, D)), LV)
ok, expect = verify_poison_full(LV, hp, delta_known)
assert ok is True and delta_known in expect
assert verify_poison_full(LV, hp, 9999)[0] is False     # 非法毒跳
assert verify_poison_full(99, 808, 10) == (False, set())  # 不可能是满档
assert verify_poison_full(LV, hp, "xx")[0] is False
print("OK：毒跳反查满档 / 非法与非满档拒绝")

# ★ 猛毒 Δhp 实测表回归（95~105 级）
# 口径以用户给的实测表为准：
#   C:/Users/ptelegion/Downloads/巴朵兰恩_95-105_MAXHP_猛毒DeltaHP.json
# 公式：K=(lv-1)*4+27，掉血=(K*(V+S+T+D)//100 - 20)//4，满档四维和恒为 123。
# ⚠ 别拿面板值（hp / grow_stats 的攻防敏）去代公式，那两套口径对不上。
DELTA_HP_TABLE = {95: 118, 96: 120, 97: 121, 98: 122, 99: 123, 100: 125,
                  101: 126, 102: 127, 103: 128, 104: 129, 105: 131}
# derived 只吃 sum(base)，随便一组和为 123 的满档加点都行（这里 10 点全加体）
_probe = (0, 0, 0, 0, (35, 39, 22, 27))
for lv, exp in sorted(DELTA_HP_TABLE.items()):
    got = poison_dmg(_probe, lv, "derived")
    assert got == exp, f"Lv{lv} 实测表 {exp}，公式算出 {got}"
print(f"OK：猛毒 Δhp 实测表 95~105 级 {len(DELTA_HP_TABLE)} 条逐条吻合"
      f"（{min(DELTA_HP_TABLE.values())}~{max(DELTA_HP_TABLE.values())}）")

# ---- 规则匹配 ----
print("--- 规则匹配 ---")
rule = parse_catch_rule_text(CATCH_SAMPLE_TEXT)
rules = {rule["name"]: rule}
assert rule["name"] == "巴朵兰恩" and rule["enabled"] is True
assert 797 in rule["levels"][95]["max_hp"]        # 样本第一对 95|797
unit = {"name": "巴朵兰恩", "lv": 95, "hpmax": 797}
assert match_catch_rule(unit, rules) == (True, "命中规则")
assert match_catch_rule({**unit, "hpmax": 99999}, rules)[0] is False
assert match_catch_rule({**unit, "lv": 94}, rules)[0] is False
assert match_catch_rule(
    {"name": "乌力", "lv": 95, "hpmax": 797}, rules)[0] is False
off = {"巴朵兰恩": {**rule, "enabled": False}}
assert match_catch_rule(unit, off) == (False, "规则未启用")
print("OK：名字 / 等级 / maxHP 三项与启用开关")

# ---- build_drop_l2 ----
print("--- build_drop_l2 ---")
assert build_drop_l2(68, 35, "K0") == "68|35|0|103"    # 文档样例
assert build_drop_l2(15, 14, "K2") == "15|14|2|31"     # 文档样例
assert build_drop_l2(15, 14, 2) == "15|14|2|31"        # 整数槽位
assert build_drop_l2(15, 14, "k2") == "15|14|2|31"     # 小写
assert build_drop_l2(15, 14, " K2 ") == "15|14|2|31"   # 空白
assert build_drop_l2(1, 2, "K5") is None               # 槽位越界
assert build_drop_l2(1, 2, 5) is None
assert build_drop_l2(1, 2, "xx") is None
print("OK：L2 明文与校验和 x+y+slot")

print()
print("RESULT: PASS —— test_pet 全部通过")
