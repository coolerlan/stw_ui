"""STW 协议转换：报文 -> 结构对象、Command -> 指令字符串（重构 v2.0 §3）。

包含（文档 §3 清单）：parse_bc / parse_bh / parse_bt / parse_map_objects /
build_round。⚠ 本模块不负责决定「是否攻击 / 是否抓宠」——
那是战斗状态机的职责，这里只做转换。
"""
from stw_config import (ALLY_SLOT_MAX, BA_MASK, ENEMY_SLOT_MAX, ENEMY_SLOT_MIN,
                        I_HAS_MOUNT, I_HP, I_HPMAX, I_LV, I_MHP, I_MHPMAX,
                        I_MLV, I_MNAME, I_NAME, I_SLOT, I_STATE, I_UID,
                        SLOT_FIELDS, SLOT_ROWS)


# -------------------------------------------------------------------------
# 报文 -> 结构
# -------------------------------------------------------------------------

def parse_bc(fields):
    """BC（战斗初始化）拆出各战斗槽的单位。

    结构（用户实测确认）：
        BC | 全局字段 | 槽1(13字段) | 槽2(13字段) | ...
    每个战斗槽固定 13 个字段，块内下标：
        0 slot         槽位（十六进制）我方 0~9，敌方 F~18
        1 name         单位名
        2 extra        附加（通常空）
        3 unit_id
        4 level
        5 hp
        6 max_hp
        7 state
        8 has_mount    1=带骑宠
        9 mount_name
       10 mount_level
       11 mount_hp
       12 mount_max_hp

    实测样本（我方 1 角色+1 骑宠+1 战宠，敌方 5 个单位）：
        BC|0|
        0|UV2D||18AD7|8C|4E1|5A9|5|1|巴朵兰恩|8C|40E|55A|   slot 0  角色+骑宠
        5|min-1||187B2|80|41F|4E3|1|0||0|0|0|               slot 5  战宠
        F|加宝格恩||18809|5A|2CA|2CA|1|0||0|0|0|            slot F  敌方
        10|加宝格恩||...                                    slot 10 敌方
        ...

    返回 dict 列表：{slot, name, uid, lv, hp, hpmax, mount}
    mount 为 None 或 {name, lv, hp, hpmax}。
    """
    body = list(fields)
    if not body:
        return []
    # 第 1 个是全局字段，之后才开始按 13 切
    body = body[1:]
    units = []
    for k in range(0, len(body) - SLOT_FIELDS + 1, SLOT_FIELDS):
        c = body[k:k + SLOT_FIELDS]
        # 健全性检查：槽位与等级/血量必须都是十六进制，否则说明切歪了
        try:
            slot = int(c[I_SLOT], 16)
            uid = c[I_UID]
            lv = int(c[I_LV], 16)
            hp = int(c[I_HP], 16)
            hpmax = int(c[I_HPMAX], 16)
        except (ValueError, IndexError):
            continue

        # 状态位（上毒要用：8 = 中毒中，0 = 毒已断，需要补 J）
        # 动作说明文档 §5.2。解不出来就当 None（不参与判定，不误判）。
        try:
            state = int(c[I_STATE], 16)
        except (ValueError, IndexError):
            state = None

        name = c[I_NAME]
        mount = None
        if c[I_HAS_MOUNT] not in ("", "0") and c[I_MNAME]:
            try:
                mount = {
                    "name": c[I_MNAME],
                    "lv": int(c[I_MLV], 16),
                    "hp": int(c[I_MHP], 16),
                    "hpmax": int(c[I_MHPMAX], 16),
                }
            except ValueError:
                mount = None

        units.append({
            "slot": slot, "name": name, "uid": uid,
            "lv": lv, "hp": hp, "hpmax": hpmax, "mount": mount,
            "state": state,
        })
    return units


def parse_bh(v):
    """解析 BH（伤害结算）。

    一条 fid=15 里可以含多段，各段以 "BH" 分隔，段内形如：
        a<行动者槽位>|r<目标槽位>|f<动作>|d<伤害>|p<参数>|FF
    槽位跟 BC 一样是十六进制（我方 0~9，敌方 F~18），
    伤害 d 也是十六进制（实测 d188 / d18B，含字母即为证）。

    返回 [(actor, target, dmg, flag)]，拿不到的记 -1。
    """
    out = []
    for seg in v.split("BH"):
        d = {}
        for tok in seg.split("|"):
            tok = tok.strip()
            if len(tok) >= 2 and tok[0] in "arfdp":
                try:
                    d[tok[0]] = int(tok[1:], 16)
                except ValueError:
                    pass
        if "a" in d or "d" in d:
            out.append((d.get("a", -1), d.get("r", -1),
                        d.get("d", 0), d.get("f", -1)))
    return out


def parse_bt(v):
    """解析 BT（抓宠结算），支持 BT 独立包和复合 fid=15 包。

    已见：
        BT|a0|rF|f1|
        BT|a0|rF|f1|bg|5|BH|...
        BY|...|BT|a0|r10|f0|BH|...

    返回 {"actor": int, "target": int, "flag": int}；解析不到返回 None。
    ⚠ f1 = 捕捉成功目前仍只是强推断，成败继续结合 K/BC 判断。
    """
    toks = [tok.strip() for tok in (v or "").split("|")]
    try:
        i = toks.index("BT")
    except ValueError:
        return None

    # BT 主段后面可能继续拼其它战斗段；遇到下一个段标记就停止。
    stop_tags = {"BA", "BB", "BC", "BD", "BE", "BF", "BG",
                 "BH", "BI", "BJ", "BK", "BL", "BM", "BN",
                 "BO", "BP", "BQ", "BR", "BS", "BT", "BU",
                 "BV", "BW", "BX", "BY", "BZ"}
    d = {}
    for tok in toks[i + 1:]:
        if tok in stop_tags:
            break
        if len(tok) >= 2 and tok[0] in "arf":
            try:
                d[tok[0]] = int(tok[1:], 16)
            except ValueError:
                pass
    if "a" not in d and "r" not in d:
        return None
    return {"actor": d.get("a", -1), "target": d.get("r", -1),
            "flag": d.get("f", -1)}


def parse_map_objects(v):
    """解析 fid=41（地图对象 / NPC 列表刷新）。

    结构是「若干段用逗号分隔」，每段 15 个字段：

        objid|map|x|y|dir|typeid|lv|flag|name|…

    实测样本里 name 有 战斗指导员 / 门票贩卖员 / 长毛象客运 / 看板 等 NPC
    与场景物件，也有其它玩家角色——正是"地图里的 NPC 有没有刷出来"的证据。

    返回 [{"name","x","y","map"}]；解析不出名字的段直接丢掉。
    """
    out = []
    for blk in (v or "").split(","):
        f = blk.split("|")
        if len(f) < 9:
            continue
        name = f[8].strip()
        if not name:
            continue
        try:
            x, y = int(f[2]), int(f[3])
        except (ValueError, IndexError):
            continue
        out.append({"name": name, "x": x, "y": y,
                    "map": f[1] if len(f) > 1 else ""})
    return out


def fid15_has_tag(v, tag):
    """fid=15 允许把多个战斗段拼在同一个字符串里。

    组队实测会出现：
        BH|...|BE|...|BY|...
        BY|...|BT|...|BH|...
    所以不能只看第一个 tag；这里按完整字段匹配，避免子串误判。
    """
    return any(tok.strip() == tag for tok in (v or "").split("|"))


def parse_ba(fields):
    """BA|value|round| -> (value, low, round)；解析不出来返回 None。

    value / round 都是十六进制。round 是会话内递增的回合计数，用来做
    「一次机会只发一次」的去重键；拿不到就记 -1（调用方不做去重）。
    """
    if not fields:
        return None
    try:
        val = int(fields[0], 16)
    except (ValueError, IndexError):
        return None
    rnd = -1
    if len(fields) > 1:
        try:
            rnd = int(fields[1], 16)
        except ValueError:
            rnd = -1
    return val, val & BA_MASK, rnd


# -------------------------------------------------------------------------
# 战斗结构 / 槽位语义辅助（parse_bc 产物的敌我划分与目标选择）
# -------------------------------------------------------------------------

def units_to_slots(units, player=None):
    """按 BC 报文里的 slot 把单位分到我方/敌方。

    units 是 parse_bc 产出的 dict 列表，每项含 slot / name / lv / hp /
    hpmax / mount。敌我只看 slot，不再用血量或名字做锚点：
        slot <= 0x9  -> 我方（0~4 角色+骑宠，5~9 战宠）
        slot >= 0xF  -> 敌方（0xF~0x18，即十进制 15~24）

    返回 (enemy_rows, ally_rows)，每行 (slot, name, lv, cur, max[, extra])。
    """
    ally_rows, enemy_rows = [], []

    for u in units:
        slot = u["slot"]
        name = u["name"] or ""
        lv, hp, hpmax = u["lv"], u["hp"], u["hpmax"]

        if ENEMY_SLOT_MIN <= slot <= ENEMY_SLOT_MAX:
            # 敌方：跳过无名（报文末尾常有残缺块）
            if not name:
                continue
            enemy_rows.append((slot, name, lv, hp, hpmax))
        elif slot <= ALLY_SLOT_MAX:
            mount = u.get("mount")
            if mount:
                # 角色 + 骑宠复合单位，合并成一行，骑宠血量作附加显示
                label = f"{name}+{mount['name']}" if mount["name"] else name
                extra = f"骑宠 {mount['hp']}/{mount['hpmax']}"
                ally_rows.append((slot, label, lv, hp, hpmax, extra))
            else:
                # 战宠（slot 5~9）
                ally_rows.append((slot, name, lv, hp, hpmax))

    ally_rows.sort(key=lambda r: r[0])
    enemy_rows.sort(key=lambda r: r[0])
    return enemy_rows[:SLOT_ROWS], ally_rows[:SLOT_ROWS]


def alive_enemy_slots(units):
    """当前 BC 里「真实存在且 HP>0」的敌方槽位，升序。

    不要无脑遍历 F~18：那只是槽位取值范围，实际有几只、哪只还活着，
    只能看最近一次 BC。槽位 F 死掉之后下一次 BC 里它就不在列表里了，
    alive_enemies 自然变成 [10, 11, 12, 13]。

    三条过滤缺一不可：
      · 槽位必须落在 [F, 18]（超出范围的不是敌方）
      · 必须有名字（报文尾部残缺块有槽位没名字）
      · hp > 0（已倒下）
    """
    out = set()
    for u in units or []:
        slot = u["slot"]

        if not (ENEMY_SLOT_MIN <= slot <= ENEMY_SLOT_MAX):
            continue
        if not u.get("name"):
            continue
        if u.get("hp", 0) <= 0:
            continue

        out.add(slot)

    return sorted(out)


def pick_enemy_target(units):
    """选目标：存活敌方里 slot 最小的那个（例：F 死了就打 10）。

    ⚠ 找不到就返回 None，**绝不返回默认的 F**。
    BC 还没到、敌人刚死、BC 更新滞后时返回 F 会生成 W|1|F 去打尸体，
    「没有合法目标时绝不发包」由调用方和 act_round() 双重保证。
    """
    alive = alive_enemy_slots(units)
    return alive[0] if alive else None


# -------------------------------------------------------------------------
# Command -> 指令字符串（一次机会 = 两条 fid=14：角色 + 战宠）
# -------------------------------------------------------------------------

# ⚠ 一次操作机会必须发 **两条** fid=14：角色指令 + 宠物指令。
# 只发一条服务器就一直等另一个单位，本回合永远不结算（战斗卡死）。
# {t} 替换成选中的敌方槽位（十六进制，不带 0x）
# ⚠ 模板表**只读**：任何运行时逻辑都禁止修改它（v2.1 §3.2）。
ROUND_CMDS = {
    "attack": ("H|{t}", "W|1|{t}"),   # 角色普攻 + 宠物技能1
    # 抓宠用最新真实抓包：T|目标（角色捕捉）+ W|1|目标（战宠配套）。
    # 旧的 C|{t} 只是占位，已废弃。
    "catch":  ("T|{t}", "W|1|{t}"),
    "flee":   ("E", "W|FF|FF"),       # 角色逃跑 + 宠物不动
    # 上毒（猛毒）—— 动作说明文档 §5 / 抓宠智能筛选 v2 §4
    #   J  = 人物精灵/技能（不是 H/T/E）
    #   {s} = 技能栏下标，本号猛毒在武器第 2 格 -> 2；换号可能不同，走配置
    #   战宠必须 W|FF|FF 待机，否则会把目标打死，就抓不到了
    "poison": ("J|{s}|{t}", "W|FF|FF"),
}

# 抓宠 + 战宠待机：上毒流程一律用它（抓宠智能筛选 v2 §9）——
# 战宠继续打会把目标打死，那就永远抓不到了。
CATCH_WAIT_CMDS = ("T|{t}", "W|FF|FF")


def build_round(mode, target=None, skill=2, pet_action="attack"):
    """Command -> 指令字符串：一次机会的两条 fid=14（角色指令 + 战宠指令）。

    {t} = 目标敌方槽位（十六进制不带 0x），无目标（仅逃跑）填 "FF"；
    {s} = 技能栏下标（上毒 J|{s}|{t} 用），默认 2，调用方从配置传。
    pet_action 只对 catch 有效："attack" 战宠跟打 W|1|{t}，
    "wait" 战宠待机 W|FF|FF（上毒流程强制 wait）。
    未知 mode 按 attack 处理，与旧内联行为一致。
    ⚠ 纯函数：ROUND_CMDS / CATCH_WAIT_CMDS 只读，禁止任何运行时修改。
    """
    if mode == "catch" and pet_action == "wait":
        tmpl = CATCH_WAIT_CMDS
    else:
        tmpl = ROUND_CMDS.get(mode, ROUND_CMDS["attack"])
    return [c.format(t=f"{target:X}" if target is not None else "FF",
                     s=skill if skill is not None else 2)
            for c in tmpl]
