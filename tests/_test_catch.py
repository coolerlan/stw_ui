"""抓宠（catch）状态机测试 —— 对应开发文档 §27 的 Case 1/2/3。

不连游戏，直接喂一串「协议事件」给同一套状态机，验证：

  Case 1  单目标抓宠成功：T/W -> BT -> K -> BC 无敌人 -> 胜利结束
  Case 2  双目标：抓掉 F 后，下一轮 BA low=0 必须继续处理 10
          （这是最重要的回归测试：BT 必须解除 round_inflight）
  Case 3  无目标：不发 T，不默认 F，走 victory_pending / finish

同时验证规则判定：名字 + 等级 + maxHP 三项同时命中才算。
"""
import os
import sys

# 仓库根 + stw_ui 包目录进 sys.path（从 __file__ 推，不写死绝对路径）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "stw_ui"))
sys.path.insert(0, _ROOT)

from stw_protocol import ROUND_CMDS  # noqa: E402  模板表归属协议层（v2.1 A1）
from stw_pet import match_catch_rule  # noqa: E402
from stw_pet import pick_catch_target  # noqa: E402
# 别再从 stw_ui 转手拿：Engine 剥离后这些符号已不属于 UI
from stw_protocol import parse_bt                            # noqa: E402
from stw_pet import (catch_match_report, CATCH_SAMPLE_TEXT,  # noqa: E402
                     parse_catch_rule_text)


def u(slot, name, lv, hp, hpmax):
    return {"slot": slot, "name": name, "lv": lv, "hp": hp, "hpmax": hpmax,
            "uid": "0", "mount": None}


# ---------------------------------------------------------------------------
# 抓宠状态机：和 stw_ui.py 的 BA/BT/K/BC 分支同一套逻辑
# ---------------------------------------------------------------------------
def run_battle(events, rules, log=True):
    """events: [(kind, payload)]，kind ∈ BC / BA / BT / K

    BA payload = low；BT payload = 原始串；BC payload = units；K payload = 名字
    """
    last_units = []
    round_inflight = False
    battle_had_enemy = False
    victory_pending = False
    last_catch_target = None
    last_catch_name = None
    catch_bt_seen = catch_k_seen = False
    catch_k_name = None
    rounds = 0
    sent = []
    finished = None
    no_match = 0

    for kind, p in events:
        if kind == "BC":
            last_units = p
            alive = [x["slot"] for x in p
                     if 0xF <= x["slot"] <= 0x18 and x["name"] and x["hp"] > 0]
            if alive:
                battle_had_enemy = True
                victory_pending = False
            elif battle_had_enemy:
                victory_pending = True
                if log:
                    print("      BC 敌方全灭 -> 等最终 BA")
        elif kind == "BA":
            low = p
            if low != 0:
                if log:
                    print(f"      BA low=0x{low:X} ACK")
                continue
            if victory_pending:
                finished = "敌方全灭"
                victory_pending = False
                round_inflight = False
                if log:
                    print("      BA low=0 -> 敌方已全灭，胜利结束")
                break
            if round_inflight:
                if log:
                    print("      BA low=0 -> 本轮尚未结算，忽略")
                continue
            unit = pick_catch_target(last_units, rules)
            if unit is None:
                no_match += 1
                if log:
                    print("      BA low=0 -> 无命中目标，按设置逃跑")
                sent.append(("flee", None))
                continue
            tgt = unit["slot"]
            last_catch_target = tgt
            last_catch_name = unit["name"]
            catch_bt_seen = catch_k_seen = False
            catch_k_name = None
            rounds += 1
            round_inflight = True
            cmds = [c.format(t=f"{tgt:X}") for c in ROUND_CMDS["catch"]]
            sent.append(("catch", cmds))
            if log:
                print(f"      BA low=0 -> 发 {cmds}（{last_catch_name}）")
        elif kind == "BT":
            round_inflight = False
            bt = parse_bt(p)
            if bt and bt["target"] == last_catch_target:
                catch_bt_seen = True
            if log:
                print(f"      BT 结算 target={bt['target'] if bt else '?'} "
                      f"flag={bt['flag'] if bt else '?'} -> 解锁下一轮")
        elif kind == "K":
            if p == last_catch_name:
                catch_k_seen = True
                catch_k_name = p
            if log:
                print(f"      K 更新 = {p}"
                      f"{'（与捕捉目标同名）' if p == last_catch_name else ''}")
        elif kind == "BH":
            round_inflight = False
            if log:
                print("      BH 伤害结算 -> 解锁下一轮")

    success = catch_k_seen and (
        catch_bt_seen
        or (last_catch_target is not None
            and last_catch_target not in
            [x["slot"] for x in last_units
             if 0xF <= x["slot"] <= 0x18 and x["name"] and x["hp"] > 0]))
    return {"sent": sent, "rounds": rounds, "finished": finished,
            "success": success, "no_match": no_match}


# ---------------------------------------------------------------------------
rule = parse_catch_rule_text(CATCH_SAMPLE_TEXT)
RULES = {rule["name"]: rule}

print("=" * 66)
print("规则库：", rule["name"], f"{len(rule['levels'])} 个等级")
print("=" * 66)

# ---- 规则判定 ----
assert match_catch_rule(u(0xF, "巴朵兰恩", 100, 913, 913), RULES)[0] is True
assert match_catch_rule(u(0xF, "巴朵兰恩", 100, 920, 920), RULES)[0] is False
assert match_catch_rule(u(0xF, "巴朵兰恩", 94, 913, 913), RULES)[0] is False
assert match_catch_rule(u(0xF, "乌力", 100, 913, 913), RULES)[0] is False
print("OK 规则判定：名字+等级+maxHP 三项同时命中才抓")

# ---- 抓宠指令必须是 T|target + W|1|target（真实抓包）----
assert ROUND_CMDS["catch"] == ("T|{t}", "W|1|{t}"), ROUND_CMDS["catch"]
print("OK 抓宠指令：", ROUND_CMDS["catch"])

# ---- Case 1：单目标抓宠成功 ----
print("\n--- Case 1：单目标（贝恩达斯）抓宠成功 ---")
BE_RULES = {
    "贝恩达斯": {
        "enabled": True,
        "levels": {1: {"max_hp": {15}}},
        "meta": [],
        "level_extra": {},
    }
}
r1 = run_battle([
    ("BC", [u(0xF, "贝恩达斯", 1, 15, 15)]),
    ("BA", 0),
    ("BA", 0x1), ("BA", 0x21),
    ("K", "贝恩达斯"),
    ("BT", "BT|a0|rF|f1|"),
    ("BC", [u(0xF, "贝恩达斯", 1, 0, 15)]),   # 已离场
    ("BA", 0),
], BE_RULES)
assert r1["sent"] == [("catch", ["T|F", "W|1|F"])], r1
assert r1["success"], r1
assert r1["finished"] == "敌方全灭", r1
assert r1["rounds"] == 1, r1
assert r1["no_match"] == 0, r1
print("   ->", r1["sent"], "成功", r1["success"], r1["finished"])
print("OK Case 1：单目标命中规则 -> T|F + W|1|F -> 捕捉成功")

# ---- Case 1b：有规则的单目标 ----
print("\n--- Case 1b：巴朵兰恩 Lv100 maxHP=913（命中规则）---")
r1b = run_battle([
    ("BC", [u(0xF, "巴朵兰恩", 100, 913, 913)]),
    ("BA", 0),
    ("BA", 0x1), ("BA", 0x21),
    ("K", "巴朵兰恩"),
    ("BT", "BT|a0|rF|f1|bg|5|BH|a10|r5|fA|d1|p0|FF|"),
    ("BC", [u(0xF, "巴朵兰恩", 100, 0, 913)]),
    ("BA", 0),
], RULES)
assert r1b["sent"] == [("catch", ["T|F", "W|1|F"])], r1b["sent"]
assert r1b["success"], r1b
assert r1b["finished"] == "敌方全灭"
print("   ->", r1b["sent"], "成功", r1b["success"], r1b["finished"])
print("OK Case 1b：T|F + W|1|F，BT 后 K 命中 -> 捕捉成功 -> 胜利结束")

# ---- Case 2：双目标，抓掉 F 后必须继续处理 10 ----
print("\n--- Case 2：双目标（F 命中 / 10 命中），抓掉 F 后继续抓 10 ---")
r2 = run_battle([
    ("BC", [u(0xF, "巴朵兰恩", 100, 913, 913), u(0x10, "巴朵兰恩", 100, 913, 913)]),
    ("BA", 0),                                    # 第 1 轮 -> 抓 F
    ("BA", 0x1), ("BA", 0x21),
    ("K", "巴朵兰恩"),
    ("BT", "BT|a0|rF|f1|"),                       # BT 必须解锁 inflight
    ("BC", [u(0x10, "巴朵兰恩", 100, 913, 913)]),  # F 已消失
    ("BA", 0x10000 & 0x3FF),                      # 下一轮窗口（值随意，low=0）
    ("BA", 0x1), ("BA", 0x21),
    ("K", "巴朵兰恩"),
    ("BT", "BT|a0|r10|f1|"),
    ("BC", [u(0x10, "巴朵兰恩", 100, 0, 913)]),
    ("BA", 0),
], RULES)
assert r2["sent"] == [("catch", ["T|F", "W|1|F"]),
                      ("catch", ["T|10", "W|1|10"])], r2["sent"]
assert r2["finished"] == "敌方全灭", r2
print("   ->", r2["sent"], r2["finished"])
print("OK Case 2：抓掉 F 后下一轮 target 自动变成 10（BT 解锁生效）")

# ---- Case 2b：有敌人但规则不命中 -> 逃跑 ----
print("\n--- Case 2b：名字命中但 maxHP 不命中 -> 逃跑 ---")
r2b = run_battle([
    ("BC", [u(0xF, "巴朵兰恩", 100, 920, 920)]),
    ("BA", 0),
], RULES)
assert r2b["sent"] == [("flee", None)], r2b
assert r2b["no_match"] == 1, r2b
print("   ->", r2b["sent"])
print("OK Case 2b：规则不命中不发 T，按默认策略逃跑")

# ---- Case 3：无目标 ----
print("\n--- Case 3：BC 无存活敌方 ---")
r3 = run_battle([
    ("BC", [u(0xF, "巴朵兰恩", 100, 913, 913)]),
    ("BC", [u(0xF, "巴朵兰恩", 100, 0, 913)]),
    ("BA", 0),
], RULES)
assert r3["sent"] == [], r3
assert r3["finished"] == "敌方全灭", r3
print("   -> 未发任何包，", r3["finished"])
print("OK Case 3：不发 T，不默认 F，走 victory_pending / finish")

# ---- 匹配预览 ----
rep = catch_match_report(
    [u(0xF, "巴朵兰恩", 100, 913, 913), u(0x10, "巴朵兰恩", 100, 920, 920),
     u(0x11, "乌力", 1, 15, 15)], RULES)
assert rep[0]["matched"] and not rep[1]["matched"] and not rep[2]["matched"]
print("\nOK 匹配预览：", [(x["name"], x["max_hp"], x["matched"]) for x in rep])

print("\nRESULT: PASS")
