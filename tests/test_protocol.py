# -*- coding: utf-8 -*-
"""§16 test_protocol.py：stw_protocol 纯函数覆盖。

覆盖清单（v2.1 §16）：
    BC解析 / BA解析 / BH解析 / BT解析 /
    alive_enemy_slots / pick_enemy_target / build_round
纯函数测试：不起进程、不连游戏、不碰 Tk。
"""
import os
import sys

# 仓库根 + stw_ui 包目录进 sys.path（从 __file__ 推，不写死绝对路径）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "stw_ui"))
sys.path.insert(0, _ROOT)

from stw_config import BA_MASK  # noqa: E402
from stw_protocol import (ROUND_CMDS, alive_enemy_slots, build_round,  # noqa: E402
                          parse_ba, parse_bc, parse_bh, parse_bt,
                          pick_enemy_target)

# ---- BC 解析 ----
print("--- BC 解析 ---")
# 实测样本（parse_bc 文档串）：全局字段 + 三个 13 字段块
fields = [
    "0",                                                    # 全局字段
    "0", "UV2D", "", "18AD7", "8C", "4E1", "5A9", "5", "1",  # slot0 角色+骑宠
    "巴朵兰恩", "8C", "40E", "55A",
    "5", "min-1", "", "187B2", "80", "41F", "4E3", "1", "0",  # slot5 战宠
    "", "0", "0", "0",
    "F", "加宝格恩", "", "18809", "5A", "2CA", "2CA", "1", "0",  # slotF 敌方
    "", "0", "0", "0",
]
units = parse_bc(fields)
assert len(units) == 3, units
u0, u5, uf = units
assert u0["slot"] == 0 and u0["name"] == "UV2D" and u0["uid"] == "18AD7"
assert u0["lv"] == 0x8C and u0["hp"] == 0x4E1 and u0["hpmax"] == 0x5A9
assert u0["state"] == 5
assert u0["mount"] == {"name": "巴朵兰恩", "lv": 0x8C,
                       "hp": 0x40E, "hpmax": 0x55A}
assert u5["slot"] == 5 and u5["mount"] is None and u5["lv"] == 0x80
assert uf["slot"] == 15 and uf["name"] == "加宝格恩"
assert uf["hp"] == uf["hpmax"] == 0x2CA
assert parse_bc([]) == []
# 等级非十六进制 -> 整块当残块丢弃，不误切后续
bad = ["0", "0", "怪", "", "1234", "ZZ", "4E1", "5A9", "5", "0",
       "", "0", "0", "0"]
assert parse_bc(bad) == []
print("OK：13 字段切块 / 骑宠合并 / 残块跳过")

# ---- BA 解析 ----
print("--- BA 解析 ---")
assert parse_ba(["18000", "3"]) == (0x18000, 0x18000 & BA_MASK, 3)
assert parse_ba(["18000", "3"])[1] == 0          # low=0：本条不带任何已发指令
assert parse_ba(["18021", "3"]) == (0x18021, 0x21, 3)   # 角色+宠都已发
assert parse_ba([]) is None
assert parse_ba(["GG"]) is None                  # value 非十六进制
assert parse_ba(["1", "GG"]) == (1, 1, -1)       # round 拿不到记 -1
assert parse_ba(["1"]) == (1, 1, -1)             # 没有 round 字段
print("OK：value / low / round")

# ---- BH 解析 ----
print("--- BH 解析 ---")
assert parse_bh("BH|a10|rF|fA|d1|p0|FF|") == [(0x10, 0xF, 1, 0xA)]
assert parse_bh("BH|a0|rF|f1|d5|FF|BH|a1|r10|f2|dA|FF|") == \
    [(0, 15, 5, 1), (1, 0x10, 0xA, 2)]           # 一条里多段
assert parse_bh("BH|rF|d1|FF|") == [(-1, 15, 1, -1)]   # 缺 a/f 记 -1
assert parse_bh("") == []
print("OK：多段 / 伤害十六进制 / 缺字段容错")

# ---- BT 解析 ----
print("--- BT 解析 ---")
assert parse_bt("BT|a0|rF|f1|") == {"actor": 0, "target": 15, "flag": 1}
assert parse_bt("BT|a0|rF|f1|bg|5|BH|a0|rF|f1|d5|FF|") == \
    {"actor": 0, "target": 15, "flag": 1}        # 复合包在下一段标记停
assert parse_bt("BY|x|BT|a0|r10|f0|BH|a0|rF|d1|FF|") == \
    {"actor": 0, "target": 0x10, "flag": 0}      # BT 不在开头也能认
assert parse_bt("BC|0|") is None
assert parse_bt("BT|f1|") is None                # 只有 f 不算
print("OK：独立包 / 复合包 / 非 BT")

# ---- alive_enemy_slots / pick_enemy_target ----
print("--- alive_enemy_slots / pick_enemy_target ---")
units = [
    {"slot": 0, "name": "UV2D", "hp": 100},        # 我方，不算
    {"slot": 15, "name": "加宝格恩", "hp": 714},
    {"slot": 16, "name": "乌力", "hp": 0},          # 已倒下
    {"slot": 17, "name": "", "hp": 5},              # 无名残块
    {"slot": 18, "name": "布依伦", "hp": 30},
]
assert alive_enemy_slots(units) == [15, 18]
assert pick_enemy_target(units) == 15              # 存活里 slot 最小
dead = [{"slot": 15, "name": "x", "hp": 0},
        {"slot": 16, "name": "y", "hp": -1}]
assert alive_enemy_slots(dead) == []
assert pick_enemy_target(dead) is None             # 绝不默认 F
assert pick_enemy_target([]) is None
assert alive_enemy_slots(None) == []
print("OK：三条过滤 / 目标选择 / 无目标返回 None")

# ---- build_round ----
print("--- build_round ---")
before = {k: tuple(v) for k, v in ROUND_CMDS.items()}
assert build_round("attack", 15) == ["H|F", "W|1|F"]
assert build_round("attack", 0x10) == ["H|10", "W|1|10"]
assert build_round("catch", 15) == ["T|F", "W|1|F"]       # 默认 pet 跟打
assert build_round("catch", 15, pet_action="wait") == ["T|F", "W|FF|FF"]
assert build_round("poison", 16, skill=2) == ["J|2|10", "W|FF|FF"]
assert build_round("poison", 16, skill=5) == ["J|5|10", "W|FF|FF"]
assert build_round("poison", 16, skill=None) == ["J|2|10", "W|FF|FF"]
assert build_round("flee") == ["E", "W|FF|FF"]
assert build_round("flee", 15) == ["E", "W|FF|FF"]        # 逃跑不需要目标
assert build_round("attack", None) == ["H|FF", "W|1|FF"]  # 无目标填 FF
assert build_round("no_such_mode", 15) == ["H|F", "W|1|F"]  # 未知按 attack
# ⚠ ROUND_CMDS 只读：全部调用后模板必须原封不动（v2.1 §3.2）
assert {k: tuple(v) for k, v in ROUND_CMDS.items()} == before
print("OK：一次两条 fid14 / catch+wait / 模板只读")

print()
print("RESULT: PASS —— test_protocol 全部通过")
