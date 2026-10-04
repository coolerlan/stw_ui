"""宠物逻辑（重构 v2.0 §3.3）：K0~K4 解析、满档计算、猛毒四维验证、
抓宠规则、丢宠明文。

只依赖 stw_config（v2.1 §3.3）：不碰底层游戏模块 / UI / 战斗状态机 / Frida。
"""
import json
import os

from stw_config import BASE_DIR, CATCH_RULES_FILE, ENEMY_SLOT_MAX, ENEMY_SLOT_MIN


# ---------------------------------------------------------------------------
# 抓宠（catch）
# ---------------------------------------------------------------------------
# 抓宠不是一套新的战斗系统，只是现有状态机里的第三种动作：
#   BA low=0 -> 按规则选目标 -> T|slot + W|1|slot -> BT 结算 -> Kx/BC -> 下一轮
# 复用已有的 round_inflight / victory_pending / finish / fid=8，不另起一套。


# 「载入示例」按钮用的数据，同时也是测试里批量导入解析的夹具。
# 口径来源：data/巴朵兰恩_95-105_MAXHP_猛毒DeltaHP.json（权威表，与公式逐条吻合）
# ⚠ 2026-10-04 修过一个错：原来写 96:119 / 97:120，与公式和权威表都不符
#   （(95*4+27)*123//100-20)//4 = 120、((96*4+27)*123//100-20)//4 = 121）。
#   点「载入示例」会把这张表写进你的规则库，错了就是漏抓/误抓。
CATCH_SAMPLE_TEXT = """巴朵兰恩
27,23,37,20,25
95:118,96:120,97:121,98:122,99:123,100:125,101:126,102:127,103:128,104:129,105:131
95|797,95|810,95|822,95|834,95|846,95|858,95|870,95|882,95|894,95|906,95|918
96|805,96|818,96|830,96|842,96|854,96|866,96|879,96|891,96|903,96|915
97|813,97|826,97|838,97|850,97|863,97|875,97|887,97|900,97|912,97|924,97|937
98|821,98|834,98|846,98|859,98|871,98|883,98|896,98|908,98|921,98|933,98|946
99|829,99|842,99|854,99|867,99|879,99|892,99|905,99|917,99|930,99|942,99|955
100|837,100|850,100|862,100|875,100|888,100|900,100|913,100|926,100|939,100|951,100|964
101|845,101|858,101|871,101|883,101|896,101|909,101|922,101|935,101|947,101|960,101|973
102|853,102|866,102|879,102|892,102|905,102|918,102|930,102|943,102|956,102|969,102|982
103|861,103|874,103|887,103|900,103|913,103|926,103|939,103|952,103|965,103|978,103|991
104|869,104|882,104|895,104|908,104|921,104|935,104|948,104|961,104|974,104|987,104|1000
105|877,105|890,105|903,105|917,105|930,105|943,105|956,105|970,105|983,105|996,105|1010"""


def parse_k_name(v):
    """从 fid=46 的 Kx 记录里取尾部宠物名。

    实测两种：
        K0|1|100274|1042|1251|0|0|...|10        （纯数值，取不到名字）
        K1|...|贝恩达斯||                        （尾部是宠物名）
    只接受「最后一个非空字段且不是纯数字」，取不到返回 None。
    """
    toks = [t.strip() for t in v.split("|") if t.strip()]
    if len(toks) < 2:
        return None
    last = toks[-1]
    if not last or last.isdigit():
        return None
    return last


# ---------------------------------------------------------------------------
# 宠物栏（UI宠物栏.md）：K0~K4 解析 + 满档判定（是否满档.md）
# ---------------------------------------------------------------------------
PET_SLOTS = ["K0", "K1", "K2", "K3", "K4"]

# K 包字段位置表（STW_K包宠物解析开发文档_v2.md §3）。
# ⚠ v1 文档把「等级」放在第 2 段是错的：那段其实是**当前 HP**。
#    实测对照（同一只宠的两种包）：
#      长包 K3|1|100373|1209|1306|0|0|18153|-1|140|327|215|190|100|...
#      短包 K3|xZa|1256|0|18153|327|215|190|100|0|20|80|0|
#      -> 短包第 2 段 1256 落在长包的 hp(1209)~hp_max(1306) 之间，是 HP 不是等级；
#         5~8 段 327/215/190/100 正好是长包的 atk/def/agi/loyalty。
# 短包是「紧凑更新」，**没有等级也没有名字**，只能覆盖数值。
PET_K_FIELDS = {
    "long": {"type": 1, "pet_id": 2, "hp": 3, "hp_max": 4, "exp": 5, "unk": 6,
             "uid1": 7, "uid2": 8, "level": 9, "atk": 10, "def": 11,
             "agi": 12, "loyalty": 13, "name": 20, "title": 21},
    "short": {"hp": 2, "uid1": 4, "atk": 5, "def": 6, "agi": 7, "loyalty": 8},
}

# 巴朵兰恩 enemybase：体23 腕37 耐20 敏25，野生生成每项浮动 ±2
# -> 满档 = 体25 腕39 耐22 敏27（是否满档.md §2）
FULL_BASE = (25, 39, 22, 27)                 # (vital, str, tough, dex)
BASE_RANGE = (range(21, 26),                 # vital
              range(35, 40),                 # str
              range(18, 23),                 # tough
              range(23, 28))                 # dex
_PET_FULL_CACHE = {}


def distribute_10_points():
    """野生生成后额外 10 点随机分配到四项的所有组合（a+b+c+d=10，共 286 种）。"""
    for a in range(11):
        for b in range(11 - a):
            for c in range(11 - a - b):
                yield a, b, c, 10 - a - b - c


def grow_stats(level, V, S, T, D):
    """成长公式：原始四维 (体/腕/耐/敏) -> 面板 (HP, 攻, 防, 敏)。

    ⚠ 这是**唯一**的成长公式来源：is_full_pet() 和测试都走这里。
    早期版本在 is_full_pet 里写一份、测试里另写一份（K*S//100 简化版），
    两边口径一分叉，测试就变成「拿错误算法自洽」——看着全绿，实际判不出满档。

    攻/防带交叉项（不是单纯的 K*S//100）：
        攻 = 腕*K*1% + 耐*K*1%*10% + 体*K*1%*10% + 敏*K*1%*5%
        防 = 耐*K*1% + 腕*K*1%*10% + 体*K*1%*10% + 敏*K*1%*5%
        敏 = 敏*K*1%
        HP = (体*4 + 腕 + 耐 + 敏) * K * 1%
    """
    K = (int(level) - 1) * 4 + 27
    v, s, t, d = K * V, K * S, K * T, K * D
    return (int((v * 4 + s + t + d) * 0.01),
            int(s * 0.01 + t * 0.01 * 0.1 + v * 0.01 * 0.1 + d * 0.01 * 0.05),
            int(t * 0.01 + s * 0.01 * 0.1 + v * 0.01 * 0.1 + d * 0.01 * 0.05),
            int(d * 0.01))


def is_full_pet(level, hp, atk, defense, agi):
    """
    严格满档判定：
    True =
        至少存在一个源码允许的生成方案，并且所有能够生成该面板的方案，四围 ±2 随机都必须全部取最高值。
    False =
        1. 没有任何合法生成方案；
        2. 或者存在至少一个非满档方案也能得到相同面板。
    """
    try:
        level = int(level)
        hp = int(hp)
        atk = int(atk)
        defense = int(defense)
        agi = int(agi)
    except (TypeError, ValueError):
        return False
    if level < 1:
        return False
    key = (level, hp, atk, defense, agi)
    hit = _PET_FULL_CACHE.get(key)
    if hit is not None:
        return hit
    # 四项 ±2 全取最高
    FULL_BASE = (25, 39, 22, 27)
    found = False
    # 枚举源码允许的 ±2（= enemybase (23,37,20,25) 各 ±2，即 BASE_RANGE）
    for v0 in BASE_RANGE[0]:
        for s0 in BASE_RANGE[1]:
            for t0 in BASE_RANGE[2]:
                for d0 in BASE_RANGE[3]:
                    for av, ast, at_, ad in distribute_10_points():
                        Vp = v0 + av
                        Sp = s0 + ast
                        Tp = t0 + at_
                        Dp = d0 + ad
                        # 成长公式只有 grow_stats 一份，别在这里再抄一遍
                        calc_hp, calc_atk, calc_def, calc_agi = \
                            grow_stats(level, Vp, Sp, Tp, Dp)
                        if calc_hp != hp:
                            continue
                        if calc_atk != atk:
                            continue
                        if calc_def != defense:
                            continue
                        if calc_agi != agi:
                            continue
                        # 找到了一个合法生成方案
                        found = True
                        # 只要存在一个非满档方案，
                        # 就无法仅凭面板确定是满档。
                        if (v0, s0, t0, d0) != FULL_BASE:
                            _PET_FULL_CACHE[key] = False
                            return False
    # 没有匹配方案 -> False
    # 有匹配方案且全部都是 FULL_BASE -> True
    _PET_FULL_CACHE[key] = found
    return found




def full_stat_combos(level, max_hp):
    """枚举所有能生成 (level, max_hp) 的**满档**四维组合。

    返回 [(hp, atk, def, agi, (V,S,T,D)), ...]；
    若该 (等级, HP上限) 根本不可能是满档（例如 Lv99/808），返回空列表 ——
    那说明第一层筛选放进来的是一只非满档宠，验证应当判不通过。

    ⚠ 元组第 1 项 hp 是 **HP上限**（只用于规则白名单匹配），不是「体」；
    毒伤公式里的「体」= K * V // 100，见 poison_dmg()。

    ⚠ atk/def/agi **必须**走 grow_stats（带交叉项），不能用 K*S//100：
    实测样本 Lv104/HP882 的真面板是 攻204 防141 敏144，而 K*S//100 只能算出
    攻171 —— 旧口径连真实存在的满档宠都判不出来。
    """
    try:
        level, max_hp = int(level), int(max_hp)
    except (TypeError, ValueError):
        return []
    if level < 1:
        return []
    v0, s0, t0, d0 = FULL_BASE
    out = []
    for av, ast, at_, ad in distribute_10_points():
        V, S, T, D = v0 + av, s0 + ast, t0 + at_, d0 + ad
        hp, atk, dfn, agi = grow_stats(level, V, S, T, D)
        if hp != max_hp:
            continue
        out.append((hp, atk, dfn, agi, (V, S, T, D)))
    return out


def poison_dmg(stats, level, mode="derived"):
    """按毒伤公式算一跳伤害。stats 是 full_stat_combos 的元素。

    derived 口径（**以用户实测表为准**，表在
    C:/Users/ptelegion/Downloads/巴朵兰恩_95-105_MAXHP_猛毒DeltaHP.json）：

        K = (level - 1) * 4 + 27
        掉血 = (K * (V+S+T+D) // 100 - 20) // 4
        满档四维原始和恒为 25+39+22+27+10 = 123
        -> 掉血 = (K * 123 // 100 - 20) // 4   ← 每个等级**只有一个值**

    对照用户的表（95~105 级）：118 120 121 122 123 125 126 127 128 129 131，
    本函数逐条吻合。

    ⚠ 别再把面板数值（hp / grow_stats 的攻防敏）代进这个公式：
      1. hp 是 HP上限，约是「体」的 4 倍，代进去预期 Δhp 会偏大约 2.6 倍；
      2. 攻/防/敏 用 grow_stats（带交叉项）会把总量抬到 ~600，
         算出 145/146 这类值，**与实测表不符**。
      毒伤公式的四项和就是「原始四维和 × K%」，与面板展示值不是一套口径。

    mode="base" 时用原始四维之和（V+S+T+D），不做成长换算（恒 25，无区分力）。
    """
    _hp, _atk, _dfn, _agi, base = stats
    if mode == "base":
        total = sum(base)
    else:
        K = (int(level) - 1) * 4 + 27
        total = (K * sum(base)) // 100   # 注意：不是 hp，也不是面板攻防敏
    return max(1, (total - 20) // 4)


def verify_poison_full(level, max_hp, delta, mode="derived"):
    """用毒跳 Δhp 反查这只宠是不是满档（文档 §7）。

    输入：等级、HP上限、Δhp（HP_before - HP_after）
    返回 (是否通过, 预期毒伤集合)。预期集合为空 = 该等级+HP上限不可能是满档。
    """
    combos = full_stat_combos(level, max_hp)
    if not combos:
        return False, set()
    try:
        delta = int(delta)
    except (TypeError, ValueError):
        return False, set()
    expect = {poison_dmg(c, level, mode) for c in combos}
    return (delta in expect), expect


def _looks_numeric(s):
    """称号位偶尔塞的是「56.13.10.6」这类数值串，不该拼进显示名。"""
    return bool(s) and all(c in "0123456789.-" for c in s)


def parse_k_pet(v):
    """解析 fid=46 的 Kx 宠物包（v2 文档 §3 / §6）。

    两种形态（同一槽位都会来）：

      长包 >=22 段：K0|1|100274|1251|1251|0|0|8298128|68487425|128|
                    216|356|50|100|...|石龟|min-1|
                    2=宠物ID 3=当前HP 4=最大HP 9=等级 10=攻击 11=防御
                    12=敏捷 13=忠诚 20=名字 21=称号
      短包 14 段 ：K3|xZa|1256|0|18153|327|215|190|100|0|20|80|0|
                    2=HP 5=攻击 6=防御 7=敏捷 8=忠诚（无等级/无名字）

    返回 dict；空槽（K2|0|）/ 非宠物包 / 等级为 0 -> None。
    `name` 是带称号的显示名（"石龟 min-1"），`base_name` 是纯名字，
    抓宠证据要用 base_name 比对，否则 "石龟 min-1" != "石龟"。
    """
    f = (v or "").split("|")
    if not f:
        return None
    slot = f[0].strip()
    if slot not in PET_SLOTS:
        return None

    def num(i):
        try:
            return int(str(f[i]).strip())
        except (ValueError, IndexError, TypeError):
            return None

    if len(f) >= 22:                       # 长包：完整记录
        idx = PET_K_FIELDS["long"]
        level = num(idx["level"])
        if level is None or level <= 0:
            return None
        base = (f[idx["name"]] or "").strip()
        title = ""
        if len(f) > idx["title"]:
            title = (f[idx["title"]] or "").strip()
        name = base
        if title and not _looks_numeric(title):
            name = f"{base} {title}" if base else title
        return {
            "slot": slot,
            "name": name or None,
            "base_name": base or None,
            "title": title,
            "level": level,
            "hp": num(idx["hp"]) or 0,
            "hp_max": num(idx["hp_max"]) or 0,
            "atk": num(idx["atk"]) or 0,
            "def": num(idx["def"]) or 0,
            "agi": num(idx["agi"]) or 0,
            "loyalty": num(idx["loyalty"]),
            "pet_id": num(idx["pet_id"]),
            "partial": False,      # 完整记录
            "full": False,         # 由调用方按需填 is_full_pet()
        }

    if len(f) >= 9:                        # 短包：只有数值的紧凑更新
        idx = PET_K_FIELDS["short"]
        return {
            "slot": slot,
            "name": None, "base_name": None, "title": "",
            "level": None,                 # 短包没有等级
            "hp": num(idx["hp"]) or 0,
            "hp_max": 0,
            "atk": num(idx["atk"]) or 0,
            "def": num(idx["def"]) or 0,
            "agi": num(idx["agi"]) or 0,
            "loyalty": num(idx["loyalty"]),
            "pet_id": None,
            "partial": True,
            "full": False,
        }
    return None


parse_pet_k = parse_k_pet      # 旧名兼容（v1 文档里的叫法）


# ---------------------------------------------------------------------------
# 丢弃宠物（丢弃宠物.MD §1）：C>S fid=21
# ---------------------------------------------------------------------------
# L2 明文： x|y|slot|x+y+slot       slot: 0=K0 … 4=K4
#   68,35,K0 -> 68|35|0|103
#   15,14,K2 -> 15|14|2|31
# 只丢有宠的槽；不带名字 / pet_id / uid。组好 L2 再走现有 L1 编码器。
def build_drop_l2(x, y, slot) -> str | None:
    """丢弃 Kx 的 L2 明文。槽位非法返回 None（调用方据此拒发）。

    槽位接受 "K0"~"K4"（大小写/空白不敏感）或 0~4 整数——与旧版
    slot_index() 输入语义一致，但用 PET_SLOTS 自解析
    （v2.1 §3.3：宠物算法层不许依赖底层游戏模块）。
    """
    if isinstance(slot, int):
        s = f"K{slot}" if 0 <= slot <= 4 else None
    else:
        s = str(slot).strip().upper()
    try:
        i = PET_SLOTS.index(s)
    except ValueError:
        return None
    x, y = int(x), int(y)
    return f"{x}|{y}|{i}|{x + y + i}"


def pet_slot_of(v) -> str | None:
    """从 fid=46 的 Kx 报文里取槽位（"K0".."K4"），非 K 包返回 None。"""
    s = (v or "").split("|", 1)[0].strip()
    return s if s in PET_SLOTS else None


def match_catch_rule(unit, rules):
    """抓宠规则判定：名字 + 等级 + maxHP 三项同时命中才算。

    unit 是 parse_bc 产出的 dict（含 name / lv / hpmax）。
    返回 (是否命中, 原因文本)。
    """
    name = unit.get("name") or ""
    level = unit.get("lv")
    max_hp = unit.get("hpmax")

    pet_rule = rules.get(name)
    if not pet_rule:
        return False, "名称不匹配（没有这条规则）"
    if not pet_rule.get("enabled", True):
        return False, "规则未启用"

    lv_rule = (pet_rule.get("levels") or {}).get(level)
    if not lv_rule:
        return False, f"等级 Lv{level} 不在规则中"

    allowed = lv_rule.get("max_hp") or set()
    if max_hp not in allowed:
        return False, f"Lv{level} maxHP={max_hp} 不在白名单"

    return True, "命中规则"


def catch_match_report(units, rules):
    """给 UI 的「当前战斗匹配预览」用：每个存活敌方命中与否 + 原因。"""
    out = []
    for u in units or []:
        slot = u.get("slot", -1)
        if not (ENEMY_SLOT_MIN <= slot <= ENEMY_SLOT_MAX):
            continue
        if not u.get("name"):
            continue
        if u.get("hp", 0) <= 0:
            continue
        ok, reason = match_catch_rule(u, rules)
        out.append({
            "slot": slot, "name": u.get("name"), "level": u.get("lv"),
            "hp": u.get("hp"), "max_hp": u.get("hpmax"),
            "matched": ok, "reason": reason,
        })
    return out


def pick_catch_target(units, rules, exclude=None):
    """从最新 BC 里挑符合抓宠规则的目标（多个命中取最小 slot）。

    exclude：已排除的槽位集合（上毒四维验证失败会排除该目标，文档 §7）。
    """
    matched = []
    for u in units or []:
        slot = u.get("slot", -1)
        if not (ENEMY_SLOT_MIN <= slot <= ENEMY_SLOT_MAX):
            continue
        if u.get("hp", 0) <= 0:
            continue
        if exclude and slot in exclude:
            continue
        ok, _reason = match_catch_rule(u, rules)
        if ok:
            matched.append(u)
    if not matched:
        return None
    return min(matched, key=lambda x: x["slot"])


def unit_by_slot(units, slot):
    """按槽位取最新 BC 里的单位；不存在返回 None。"""
    for u in units or []:
        if u.get("slot") == slot:
            return u
    return None


def parse_catch_rule_text(text):
    """批量导入解析器（文档 §18.9）。

        第1行：宠物名字
        第2行：meta
        第3行：level_extra（lv:value,...）
        第4行及以后：lv|maxHP 对（可换行）
    meta / level_extra 第一版只保存，不参与抓宠筛选。
    """
    lines = [x.strip() for x in text.splitlines() if x.strip()]
    if len(lines) < 4:
        raise ValueError("至少要有 4 行：名字 / meta / level_extra / level|maxHP")

    name = lines[0]
    meta = [int(x) for x in lines[1].split(",") if x.strip()]

    level_extra = {}
    for item in lines[2].split(","):
        item = item.strip()
        if not item:
            continue
        lv, value = item.split(":", 1)
        level_extra[int(lv)] = int(value)

    levels = {}
    hp_items = ",".join(lines[3:])
    for item in hp_items.split(","):
        item = item.strip()
        if not item:
            continue
        lv, hp = item.split("|", 1)
        lv, hp = int(lv), int(hp)
        levels.setdefault(lv, {"max_hp": set()})
        levels[lv]["max_hp"].add(hp)

    return {
        "name": name, "enabled": True,
        "meta": meta, "level_extra": level_extra, "levels": levels,
    }


def catch_rules_to_json(rules):
    """set 不能直接 JSON 序列化 -> 转 list；等级 key 转字符串。"""
    out = {}
    for name, r in (rules or {}).items():
        levels = {}
        for lv, lr in (r.get("levels") or {}).items():
            levels[str(lv)] = {
                "max_hp": sorted(int(x) for x in (lr.get("max_hp") or set()))
            }
        out[name] = {
            "enabled": bool(r.get("enabled", True)),
            "levels": levels,
            "meta": list(r.get("meta") or []),
            "level_extra": {str(k): int(v)
                            for k, v in (r.get("level_extra") or {}).items()},
        }
    return out


def catch_rules_from_json(obj):
    """JSON 反过来：等级 key 转 int，maxHP list 转 set。"""
    out = {}
    for name, r in (obj or {}).items():
        levels = {}
        for lv, lr in (r.get("levels") or {}).items():
            levels[int(lv)] = {"max_hp": set(int(x) for x in lr.get("max_hp", []))}
        out[name] = {
            "enabled": bool(r.get("enabled", True)),
            "levels": levels,
            "meta": list(r.get("meta") or []),
            "level_extra": {int(k): int(v)
                            for k, v in (r.get("level_extra") or {}).items()},
        }
    return out


def load_catch_rules(path=None):
    path = path or os.path.join(BASE_DIR, CATCH_RULES_FILE)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return catch_rules_from_json(json.load(f))
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def save_catch_rules(rules, path=None):
    path = path or os.path.join(BASE_DIR, CATCH_RULES_FILE)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(catch_rules_to_json(rules), f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False

