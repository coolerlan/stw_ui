"""回放真实战斗报文，验证 BA 应答规则 + BC 动态选目标。

跑法：python _test_ba.py [日志.jsonl] [模式]
默认 stw_ui_log.jsonl / attack。

⚠ 本文件必须和 stw_ui.py 用**同一套协议状态机**，不许再用时间去重：
   round_inflight = False  可以接受新的 BA low=0
   round_inflight = True   本轮 H/W 已发，等 BH/BJ 结算
（实测第二回合的 BA|18000|1| 距上一轮发包只有 0.153s，任何时间阈值都会
 把它当成重复窗口吞掉——这正是之前自动攻击卡死的直接原因）

⚠ 证据强度取决于日志来源：
  · 手动正常操作 / 干净登录后的自动攻击 -> 最有价值
  · 状态已经错乱的日志                  -> 先修状态再重抓
验证拆成两项：行动机会的数量/时机（BA 规则）+ 目标策略（选目标策略）。
"""
import json
import os
import sys

# 仓库根 + stw_ui 包目录进 sys.path（从 __file__ 推，不写死绝对路径）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "stw_ui"))
sys.path.insert(0, _ROOT)

from stw_protocol import ROUND_CMDS  # noqa: E402  模板表归属协议层（v2.1 A1）
from stw_protocol import pick_enemy_target  # noqa: E402
# 别再从 stw_ui 转手拿协议常量：Engine 剥离后 stw_ui 已不再 import 它们
from stw_protocol import (parse_ba, parse_bc,  # noqa: E402
                          alive_enemy_slots)
from stw_config import BA_ACT, BA_BIT_CHAR, BA_BIT_PET  # noqa: E402

FN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    _ROOT, "stw_ui_log.jsonl")
MODE = sys.argv[2] if len(sys.argv) > 2 else "attack"

# 这份样本日志是运行产物（.gitignore 忽略了），新克隆的仓库里没有。
# 没有就明确跳过，而不是 FileNotFoundError 把回归跑红。
if not os.path.isfile(FN):
    print(f"SKIP _test_ba：找不到样本日志 {FN}")
    print("     先跑一次控制台产出 stw_ui_log.jsonl，或用 "
          "`python _test_ba.py <你的日志.jsonl>` 指定。")
    raise SystemExit(0)

# ---- 1. 读日志：保留方向，OUT 不能一开始就丢掉 ----
rows = []

for line in open(FN, encoding="utf-8", errors="replace"):
    try:
        d = json.loads(line)
    except Exception:
        continue

    rows.append((
        d.get("t", 0),
        d.get("dir", ""),
        d.get("fid"),
        d.get("s", ""),
    ))

print(f"=== {FN} · {len(rows)} 条记录 "
      f"（IN {sum(1 for r in rows if r[1] == 'IN')} / "
      f"OUT {sum(1 for r in rows if r[1] == 'OUT')}） · 模式 {MODE} ===")

# ---- 2. 单遍扫描：模拟 BA 应答，同时收集真实客户端发的 fid=14 ----
battle = 0
last_units = []
round_inflight = False       # ⚠ 协议状态，不是时间
battle_had_enemy = False     # 本场是否明确看见过敌人
victory_pending = False      # 曾经有敌人 + 最新 BC 敌方全灭
victories = 0
acts = []                    # (battle, t, rnd, tgt_hex, cmds)
real_w = []                  # (battle, t, cmd)
ba_seen = {}

for t, direction, fid, s in rows:

    if direction == "OUT":
        if fid == "14" and s.startswith("W|1|"):
            real_w.append((battle, round(t, 3), s))
        continue

    if direction != "IN":
        continue

    if fid == "7":
        battle += 1
        last_units = []
        round_inflight = False
        battle_had_enemy = False
        victory_pending = False
        print(f"\n[{t:6.2f}] --- 第 {battle} 场 ---")
        continue

    if fid != "15":
        continue

    tag = s.split("|")[0]

    if tag == "BC":
        last_units = parse_bc(s.split("|")[1:])
        alive = alive_enemy_slots(last_units)
        tgt = pick_enemy_target(last_units)
        sel = f"{tgt:X}" if tgt is not None else "无"
        print(f"[{t:6.2f}] BC {len(last_units)} 单位 "
              f"存活敌方槽={[f'{x:X}' for x in alive]} "
              f"选中={sel}")

        # 胜利判定（和 stw_ui.py 同一套逻辑）
        if alive:
            battle_had_enemy = True
            victory_pending = False
        elif battle_had_enemy:
            victory_pending = True
            print(f"[{t:6.2f}] BC 敌方全灭 -> 等最终 BA")

    elif tag == "BA":
        ba = parse_ba(s.split("|")[1:])
        if ba is None:
            print(f"[{t:6.2f}] BA 解析失败 {s}")
            continue

        _val, low, rnd = ba
        ba_seen[hex(low)] = ba_seen.get(hex(low), 0) + 1

        if low != BA_ACT:
            print(f"[{t:6.2f}] BA low=0x{low:X} ACK"
                  f"（角色{'✓' if low & BA_BIT_CHAR else '✗'}"
                  f" 宠物{'✓' if low & BA_BIT_PET else '✗'}）")
            continue

        if victory_pending:
            victories += 1
            victory_pending = False
            battle_had_enemy = False
            round_inflight = False
            print(f"[{t:6.2f}] BA low=0 -> 敌方已全灭，本场胜利结束，"
                  f"不再发 H/W")
            continue

        if round_inflight:
            print(f"[{t:6.2f}] 重复 BA low=0，本轮尚未结算 -> 忽略")
            continue

        if MODE == "flee":
            tgt = None          # 逃跑不依赖敌方目标
        else:
            tgt = pick_enemy_target(last_units)
            if tgt is None:
                print(f"[{t:6.2f}] BA low=0 回合{rnd} -> 无存活目标，不发送")
                continue

        cmds = [
            c.format(t=f"{tgt:X}" if tgt is not None else "FF")
            for c in ROUND_CMDS[MODE]
        ]

        round_inflight = True
        acts.append((battle, round(t, 3), rnd,
                     f"{tgt:X}" if tgt is not None else "-", cmds))
        print(f"[{t:6.2f}] BA low=0 回合{rnd} -> 发 {cmds}")

    elif tag in ("BH", "BJ"):
        # 结算包才是「本轮结束」的协议信号
        round_inflight = False
        print(f"[{t:6.2f}] {tag} 战斗结算 -> 开放下一轮"
              f"{'' if tag == 'BH' else '（BJ 也要认）'}")

    elif tag == "BE":
        # 逃跑等路径会收到 BE；杀光敌人不会，走 victory_pending
        round_inflight = False
        victory_pending = False
        battle_had_enemy = False
        print(f"[{t:6.2f}] BE 战斗结束")


def pet_cmd(cmds):
    """一轮里可能有两条（角色+宠物），对照真实 OUT 时取宠物那条 W|1|x。"""
    return next((c for c in cmds if c.startswith("W|1|")), cmds[0])


# ---- 3. 两边对照 ----
print("\n=== 模拟应答 ===")
for b, t, rnd, tgt, cmds in acts:
    print(f"  第{b}场 {t:8.3f}  BA round={rnd}  -> {cmds}")

if real_w:
    print("\n=== 真实客户端 OUT ===")
    for b, t, cmd in real_w:
        print(f"  第{b}场 {t:8.3f}  {cmd}")

print("\n=== 逐场对照 ===")
nb = max([b for b, *_ in acts] + [b for b, *_ in real_w] + [0])
for b in range(1, nb + 1):
    p = [pet_cmd(cmds) for bb, _, _, _, cmds in acts if bb == b]
    r = [cmd for bb, _, cmd in real_w if bb == b]
    mark = "✓" if p == r else "✗"
    print(f"  第{b}场 {mark}  预测 {len(p)} 次 {p}")
    if p != r:
        print(f"          实际 {len(r)} 次 {r}")

pred = [pet_cmd(cmds) for _, _, _, _, cmds in acts]
real = [cmd for _, _, cmd in real_w]

print("\n预测 W:", pred)
print("实际 W:", real)

# ---- 4. 拆成两项结论 ----
print("\n=== 结论 ===")

hardcoded = bool(real) and len(set(real)) == 1 and real[0].endswith("|F")
if hardcoded:
    print(f"⚠ 日志来源：所有真实 W 都是 {real[0]}，目标一项不具证据力，"
          f"只能看时机是否吻合。")
elif not real:
    print("⚠ 日志来源：没有 W|1| 的 OUT 包，无法做实际对照。")
else:
    print("日志来源：真实 W 目标有变化，是有效对照样本。")

if not real:
    print("行动机会数量/时机：无法判定")
elif len(pred) == len(real):
    print(f"行动机会数量/时机：PASS（预测 {len(pred)} 次 = 实际 {len(real)} 次）")
else:
    print(f"行动机会数量/时机：FAIL（预测 {len(pred)} 次 ≠ 实际 {len(real)} 次）")

if not real:
    print("目标策略：无法判定")
elif pred == real:
    print("目标策略：MATCH —— 预测的 W 序列与真实 OUT 完全一致")
else:
    print("目标策略：DIFFERENT —— 时机对得上但目标选择不同，"
          "只说明自动选目标策略与手动选择不同，不代表 BA 规则错")
    n = max(len(pred), len(real))
    for i in range(n):
        p = pred[i] if i < len(pred) else "<无>"
        r = real[i] if i < len(real) else "<无>"
        mark = "✓" if p == r else "✗"
        print(f"  {i + 1:02d}  {mark}  预测={p:<10} 实际={r}")

# ---- 5. 无合法目标时必须返回 None，绝不回退成 F ----
def _u(slot, hp, name="怪"):
    return {"slot": slot, "name": name, "hp": hp, "hpmax": 700}


assert pick_enemy_target([]) is None, "空 BC 不能回退成 F"
assert pick_enemy_target(None) is None
assert pick_enemy_target([_u(0xF, 0), _u(0x10, 0)]) is None, "全灭不能回退成 F"
assert pick_enemy_target([_u(0xF, 100, name="")]) is None, "无名残缺块不算目标"
assert pick_enemy_target([_u(0x19, 100)]) is None, "槽位 > 0x18 不是敌方"
assert alive_enemy_slots([_u(0x18, 100)]) == [0x18], "0x18 是合法敌方上限"
assert alive_enemy_slots([_u(0x19, 100)]) == [], "0x19 越界"
assert pick_enemy_target([_u(0x12, 5), _u(0xF, 5)]) == 0xF, "取最小存活 slot"
print("\nOK：空/全灭/无名/越界槽位 一律返回 None，不退回 F；"
      "正常情况取最小存活 slot")

# ---- 6. 模拟自身的一致性 ----
print(f"\nBA low 取值分布: {ba_seen}")
print(f"判定为「战斗胜利」的场次: {victories}")
for _, _, _, tgt, cmds in acts:
    assert len(cmds) == 2, f"一轮必须是角色+宠物两条：{cmds}"
    if MODE != "flee":
        assert tgt != "-", "非逃跑模式必须有合法目标"
print(f"OK：代发 {len(acts)} 次，每轮都是角色+宠物两条"
      f"({'逃跑不校验目标' if MODE == 'flee' else '且每次都有合法目标'})")
# ⚠ 这里刻意不再断言「相邻间隔 >= N 秒」：那是拿时间当协议状态，
# 会把 0.15s 就到的第二回合吞掉（正是之前卡死的原因）
print("\nRESULT: PASS" if (not real or pred == real) else "\nRESULT: WARN")
