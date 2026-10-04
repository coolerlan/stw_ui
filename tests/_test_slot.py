"""用真实 BC 报文验证按 slot 的解析。"""
import os
import sys

# 仓库根 + stw_ui 包目录进 sys.path（从 __file__ 推，不写死绝对路径）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "stw_ui"))
sys.path.insert(0, _ROOT)
from stw_protocol import parse_bc, units_to_slots  # noqa: E402

RAW = (
    "BC|0|0|UV2D||18AD7|8C|4E1|5A9|5|1|巴朵兰恩|8C|40E|55A|"
    "5|min-1||187B2|80|41F|4E3|1|0||0|0|0|"
    "F|加宝格恩||18809|5A|2CA|2CA|1|0||0|0|0|"
    "10|加宝格恩||18809|58|2BB|2BB|1|0||0|0|0|"
    "11|加宝格恩||18809|5A|2D9|2D9|1|0||0|0|0|"
    "12|加宝格恩||18809|58|2B3|2B3|1|0||0|0|0|"
    "13|加宝格恩||18809|58|2A5|2A5|1|0||0|0|0|"
)

f = RAW.split("|")
units = parse_bc(f[1:])          # 调用点传的是去掉 'BC' 后的字段

print("解析出 %d 个槽：" % len(units))
for u in units:
    m = u["mount"]
    ms = ""
    if m:
        ms = "  骑宠=%s Lv%d %d/%d" % (m["name"], m["lv"], m["hp"], m["hpmax"])
    print("  slot=0x%X (dec %2d)  %-8s Lv%-3d %d/%d%s"
          % (u["slot"], u["slot"], u["name"], u["lv"], u["hp"], u["hpmax"], ms))

enemy, ally = units_to_slots(units, player="UV2D")
print()
print("=== 我方（应为 slot 0 角色+骑宠、slot 5 战宠）===")
for r in ally:
    extra = r[5] if len(r) > 5 else ""
    print("  [0x%X] %-16s Lv%-4d %d/%d  %s" % (r[0], r[1], r[2], r[3], r[4], extra))
print("=== 敌方（应为 slot F,10,11,12,13 共5只）===")
for r in enemy:
    print("  [0x%X] %-16s Lv%-4d %d/%d" % (r[0], r[1], r[2], r[3], r[4]))

print()
ok_ally = len(ally) == 2 and ally[0][0] == 0 and ally[1][0] == 5
ok_enemy = len(enemy) == 5 and [r[0] for r in enemy] == [0xF, 0x10, 0x11, 0x12, 0x13]
ok_mount = len(ally) == 2 and "巴朵兰恩" in ally[0][1] and "1038" in ally[0][5]
print("我方正确:", ok_ally)
print("敌方正确:", ok_enemy)
print("骑宠合并正确:", ok_mount)
print("RESULT:", "PASS" if (ok_ally and ok_enemy and ok_mount) else "FAIL")
