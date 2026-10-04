"""STW 后台执行引擎（从 stw_ui.py 剥离，纯结构搬迁、零行为变更）。

职责：
- 附加游戏进程（frida + socket bridge）；
- 接收/解析协议包；
- 调度 BattleSession（Battle 回答「我要做什么」，Engine 回答「怎么发送」）；
- 执行 fid=1 / fid=8 / fid=14 / fid=21 等动作；
- 维护抓宠、K 包认回、丢弃、停止流程、地图同步、遇敌走位等 Engine 状态。

禁止：
- import tkinter
- import stw_ui
- 直接操作 Tk 控件

UI 通信唯一通道：`self.q.put(...)`
（队列消息的名称 / tuple 结构 / 字段顺序均已冻结，见 stw_ui 的注释）。

依赖方向：stw_ui -> stw_engine -> stw_battle（不允许反向）。
"""
import importlib.util
import json
import random
import sys
import threading
import time

# ⚠ stw_config 必须先导入：它负责把 BASE_DIR / shit/ 注册进 sys.path，
# 后面的 auto_encounter / fast_encounter / _mapdata 才找得到。
from stw_config import (ALLY_SLOT_MAX, BA_ACT, BA_BIT_CHAR, BA_BIT_PET,
                        BATTLE_TIMEOUT, CATCH_CFG_DEFAULTS, ENEMY_SLOT_MIN,
                        LOG, MAP_READY_DELAY, MAP_SYNC_FIDS,
                        MAP_SYNC_SCORE_NEED, MAP_SYNC_TIMEOUT, MAP_SYNC_WAIT,
                        MAX_BATTLE_ROUNDS, OUT_OF_WORLD_STATES, RN_MAX,
                        STOPPED_READY, STOP_PENDING, STOP_RUNNING,
                        WRITE_SITE, resolve_codec)
import auto_encounter as ae  # noqa: E402
import fast_encounter as fe  # noqa: E402
import frida  # noqa: E402
from _frida_agent import AGENT  # noqa: E402
import _mapdata as md  # noqa: E402
from stw_protocol import (parse_bc, parse_ba, parse_bh, parse_bt,  # noqa: E402
                          parse_map_objects, fid15_has_tag,
                          alive_enemy_slots)
from stw_battle import BattleSession  # noqa: E402
from stw_pet import (PET_SLOTS, build_drop_l2,  # noqa: E402
                     catch_match_report, is_full_pet, parse_k_name,
                     parse_k_pet)


# ---------------------------------------------------------------------------
# sa 编解码模块（Engine 发包/收包全部依赖它）
#
# ⚠ 不要写死 vNN 版本号：`dumpcap_realtime_stream_vNN_encounter_rescue.py`
# 每次升级都改名，写死了 import 阶段就 FileNotFoundError，控制台直接起不来
# （2026-10-02 v30 → v31 挂过一次）。统一走 stw_config.resolve_codec()。
# ---------------------------------------------------------------------------
spec = importlib.util.spec_from_file_location("sa_codec", resolve_codec())
sa = importlib.util.module_from_spec(spec)
sys.modules["sa_codec"] = sa
spec.loader.exec_module(sa)

# 跳过战斗界面：set_state(10) -> 9（内容原样搬运，禁止改动 JS）
HOOK = """
Interceptor.attach(ptr(__SITE__), {
  onEnter() { if (this.context.eax.toInt32() === 10) this.context.eax = ptr(9); }
});
""".replace("__SITE__", hex(WRITE_SITE))


# ---------------------------------------------------------------------------
# Engine 专属 helper（Engine 独占，所以跟 Engine 一起搬；
# 不能留在 stw_ui，否则 stw_engine -> stw_ui 就是循环 import）
# ---------------------------------------------------------------------------
def enc(msg: bytes) -> bytes:
    out = sa.encode_layer1(msg, rn=random.randrange(0, RN_MAX))
    assert sa.decode_layer1(out) == msg
    return out


HEXCH = set("0123456789abcdefABCDEF")


def _is_hex(tok: str) -> bool:
    return bool(tok) and all(c in HEXCH for c in tok)


def _is_name(tok: str) -> bool:
    # min-1 是 BC 中宠物的真实名字，不是分隔/损坏字段。
    return (tok == "min-1" or
            (bool(tok) and "-" not in tok and len(tok) >= 2 and not _is_hex(tok)))


def fmt_damage(acts):
    """把 parse_bh 的结果变成可读文本，例：我[0]→敌[F] 392"""
    parts = []
    for a, r, dmg, _f in acts:
        a_s = "我" if 0 <= a <= ALLY_SLOT_MAX else ("敌" if a >= ENEMY_SLOT_MIN else "?")
        r_s = "我" if 0 <= r <= ALLY_SLOT_MAX else ("敌" if r >= ENEMY_SLOT_MIN else "?")
        a_t = f"{a:X}" if a >= 0 else "?"
        r_t = f"{r:X}" if r >= 0 else "?"
        parts.append(f"{a_s}[{a_t}]→{r_s}[{r_t}] {dmg}")
    return " · ".join(parts)


# ---------------------------------------------------------------------------
# 战后自动恢复 v1 —— 固定地址 / 固定策略（战后自动恢复实施开发文档 §3）
#
# 这条链路只在「战斗结束后、角色真正回到 state=9」时才动，且全程走
# 非阻塞状态机（由 run() 主循环每 tick 推进一步），绝不在 finish() 里 sleep。
# ---------------------------------------------------------------------------

# 角色（第一版直接用绝对地址）
PLAYER_HP_ADDR = 0x02B24D80
PLAYER_MAX_HP_ADDR = 0x02B24D84
PLAYER_QI_ADDR = 0x02B24D88

# K0 骑宠。⚠ 用户已确认「宠物位置不同，HP/MaxHP 地址也会不同」，
# 所以第一版只支持 K0 = 当前骑宠；骑宠换到 K1~K4 时不保证正确。
K0_HP_ADDR = 0x02B23A5C
K0_MAX_HP_ADDR = 0x02B23A60

# 缺血阈值：文档要求「MaxHP - HP > 300」才算缺血（恰好 300 不治疗）
POST_HEAL_MISSING_HP = 300

HEAL_SKILL_SLOT = 1

# 🔥 用户 2026-10-02 确认：fid=57 的字段3（target）0=角色自己，1=宠物 K0。
# 实测反证：target=4 时角色 HP 完全不涨（stw_console_log.txt 17:37:08~17:37:37
# 连续 5 次「player 使用精灵后 HP 未上涨」，而同一时刻 fid=46 报的角色 HP
# 与内存读到的 1296 完全一致 -> 地址没问题，问题就在 target=4 不成立）。
HEAL_TARGET_PLAYER = 0

# 同上：K0 骑宠 = 1。K1/K2/K3 依次类推，但本项目只治 K0。
# ⚠ 若日后改回 None，K0 治疗会走「跳过 + warn」分支，不会发猜测包。
HEAL_TARGET_K0 = 1

# 气力判断：qi > 30 直接治疗；qi <= 30 先用药（注意不是 >=）
QI_DIRECT_HEAL_MIN = 30

# 气力不足时按 2 -> 15 顺序遍历背包槽。
# ⚠ 这不是无损读取背包类型，而是「逐格实际发 fid=17 + 观察气力是否上涨」。
# 2..15 里若放了其它可对自己使用的消耗品，可能被实际消耗。
QI_ITEM_SLOT_MIN = 2
QI_ITEM_SLOT_MAX = 15
QI_ITEM_SLOTS = tuple(range(QI_ITEM_SLOT_MIN, QI_ITEM_SLOT_MAX + 1))

# 已抓包确认：fid=17 给自己使用物品时 target=0
ITEM_TARGET_SELF = 0

RECOVERY_WAIT_MAP_TIMEOUT = 5.0
RECOVERY_ACTION_TIMEOUT = 2.0


def _action_check(x, y, arg, target):
    """fid=57 / fid=17 的字段4 = x + y + 字段2 + 字段3（文档 §6）。

    已由实包验证：60+54+7+0=121（fid=17 物品对自己用，实测气力 23 -> 83）。
    绝不能写死 121——角色走到新坐标以后校验必然变化。

    ⚠ 早期文档里那条 60+54+1+4=119 的 fid=57 样本（target=4）已作废：
    照它发的包实测角色 HP 一点没涨，用户确认为 0=角色 / 1=K0 骑宠。
    """
    return int(x) + int(y) + int(arg) + int(target)


def _build_int_l2(fid, values, key):
    """通用整数 L2 构包：`&;<fid>;<v0>;<v1>;...;#;`（未做 Layer1）。

    与 send_end8() 同一范式；发送侧统一 `self.b.send(enc(l2))`。
    """
    body = b";".join(sa.enint(int(v), key) for v in values)
    return b"&;" + str(int(fid)).encode("ascii") + b";" + body + b";#;"


def build_use_spirit_l2(x, y, skill_slot, target, key):
    """fid=57 使用精灵：`x | y | 技能格 | 目标 | check`。"""
    check = _action_check(x, y, skill_slot, target)
    return _build_int_l2(57, (x, y, skill_slot, target, check), key)


def build_use_item_l2(x, y, bag_slot, target, key):
    """fid=17 使用物品：`x | y | 背包格 | 目标 | check`。"""
    check = _action_check(x, y, bag_slot, target)
    return _build_int_l2(17, (x, y, bag_slot, target, check), key)


# ---------------------------------------------------------------------------
# 引擎（后台线程）
# ---------------------------------------------------------------------------
class Engine(threading.Thread):
    def __init__(self, cfg, q):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.q = q
        self.stop_flag = threading.Event()
        self.hook_on = False
        # —— 监听 / 执行 解耦（战斗自动化架构调整文档）——
        # battle_hook_active：进 state9 就自动挂上，一直在线，负责收包 + 维护
        #                     战斗状态（BC/BA/BH/BJ/BT/BE），但绝不发 fid=14
        # auto_ev（battle_auto_active）：只有用户点「开始自动战斗」才置位，
        #                     置位后才允许代发 fid=14 / 走位包
        self.battle_hook_active = False
        self.auto_ev = threading.Event()      # 默认 False = 只监听
        self._wait_logged = False             # 「等待开始」只打一次，别刷屏
        # —— 停止流程状态机（只在「停止」后生效，运行期间恒为 RUNNING）——
        self.stop_phase = STOPPED_READY       # 未启动 = 已停止态
        self.map_sync_score = 0
        self.map_sync_t0 = 0.0                # 进入 MAP_SYNC_WAIT 的时刻
        self.map_sync_ready_at = 0.0          # 同步分够了，再等 1.5s 的时间点
        self.map_objects = []                 # 最近一次 fid=41 解出的地图对象/NPC
        # —— 宠物栏（K0~K4）——
        self.pet_panel = {s: None for s in PET_SLOTS}
        self._pet_sig = None                  # 只在数据真的变了才推给界面
        # —— 丢弃宠物（丢弃宠物.MD）——
        self.drop_queue = []                  # 待丢弃的槽位（"K0".."K4"）
        # —— 新抓宠资料上下文（抓宠满档判定与自动丢弃_时序修正方案 §5）——
        # 与 catch_result_pending **彻底分离**：那个只管战斗统计闭环，
        # 最终 BA/BE 一到就关；这个要活到"认回刚才那只宠"为止。
        self._pend = None                     # dict，见 open_pend()
        self._decided_new_slots = set()       # 已判定过的新宠槽，防重复决策
        self._bt_flag = None                  # 最近一次 BT 的 flag（判明确失败）
        # 抓宠配置（文档 §27.1）：规则库 + 策略，统一放在 cfg["catch"] 里。
        # 默认值统一声明在 stw_config.CATCH_CFG_DEFAULTS（阈值/策略归配置管）
        c = self.cfg.setdefault("catch", {})
        for k, v in CATCH_CFG_DEFAULTS.items():
            # dict 值必须复制一份，防止多个 Engine 共享同一个 rules 字典
            c.setdefault(k, dict(v) if isinstance(v, dict) else v)
        self.catch_cfg = c
        self.catch_stats = {
            # 新 UI 统计（抓宠统计口径改造开发文档 §1）
            "hpmax_matched": 0,     # 通过第一层规则（名/等级/HP上限）的候选数
            "poison_confirmed": 0,  # verify_poison_full(ok=True) 的次数
            # 旧协议/动作统计：语义一个字都不能改，只是部分不再显示
            "attempts": 0,          # 真正发过捕捉 T 指令的次数
            "successes": 0,         # BT/K/BC 证据闭环确认捕捉成功（停止条件读它）
            "unknown": 0,           # 捕捉证据未闭环（UI 隐藏，逻辑保留）
            "no_match": 0,          # 本次决策窗口没有可用抓宠目标
            "dropped": 0,           # 真正发出过 fid=21 丢弃
        }
        self.k_names = {}          # Kx 槽位 -> 尾部宠物名，抓宠成功证据
        self.catch_stop = False    # 达到「抓到 N 只后停止」时置位，等本场收尾
        # ---- 战后自动恢复 v1（文档 §10.3）----
        # 只复用 ae.Game 已有的只读句柄（PROCESS_VM_READ|QUERY_INFORMATION），
        # 不额外 OpenProcess —— 文档 §10.4 明确「已有 reader 就不要重复打开」。
        self._recovery_pending = False
        self._recovery_state = "IDLE"
        self._recovery_deadline = 0.0
        self._recovery_before_qi = None
        self._recovery_before_hp = None
        self._recovery_target = None
        self._recovery_done_targets = set()
        self._recovery_reason = ""
        self._recovery_item_slot = None      # 本轮正在验证的背包格
        # ⚠ 气力药扫描进度是 **Engine 生命周期全局状态**，跨多场战斗共享：
        #   已经判定无效的槽位永远不再重试，绝不每场从 2 重新开始（文档 §11）。
        self._qi_scan_next_slot = QI_ITEM_SLOT_MIN   # 下一个从未判失败的槽位
        self._qi_known_slot = None                   # 已验证能让气力上涨的槽位
        # 2..15 全部走完仍无气力回复 -> 全局 break Engine.run()（文档 §12）
        self._global_break = False
        self._global_break_reason = ""

    def log(self, kind, text):
        self.q.put(("log", kind, text))

    def _set_stop_phase(self, phase, note=""):
        """切换停止流程状态并同步给界面（界面靠它显示"是不是卡住了"）。"""
        self.stop_phase = phase
        self.q.put(("stop_phase", (phase, note)))

    def stat(self, **kw):
        self.q.put(("stat", kw))

    def _push_pet_panel(self):
        """宠物栏刷新：数据没变就不推，避免 fid=46 洪水把界面刷爆。"""
        sig = []
        for s in PET_SLOTS:
            p = self.pet_panel.get(s) or {}
            sig.append((p.get("name"), p.get("level"), p.get("hp"),
                        p.get("hp_max"), p.get("atk"), p.get("def"),
                        p.get("agi"), p.get("full")))
        sig = tuple(sig)
        if sig == self._pet_sig:
            return
        self._pet_sig = sig
        self.q.put(("pet_panel", [self.pet_panel.get(s) for s in PET_SLOTS]))

    def _update_pet(self, v, new_catch=False):
        """fid=46 的 Kx -> 宠物栏。返回 True 表示解析成功。

        ⚠ 满档只对**新抓到的宠**判定（用户明确要求）：已有的宠不判 ——
        一是没意义（练过的宠属性早已偏离野生生成值，算法必然 False），
        二是省掉每个 K 包一次枚举。
        new_catch 由调用方按「抓宠尝试待闭环 + 新出现的 K 槽 + 名字对得上」
        判定，和抓宠成功证据用的是同一个条件。
        """
        slot = v.split("|", 1)[0].strip()
        if slot not in PET_SLOTS:
            return False
        pet = parse_k_pet(v)
        if pet is None:
            # 空槽（K2|0| / K4|0| 之类）或解析失败 —— 一律显示「空」
            # ⚠ 同时要把 k_names 里的槽位释放掉：抓宠证据靠
            #   「kid not in catch_k_before」判断"新出现的槽"，如果丢宠后
            #   不清这条，同一槽位再抓到新宠会被当成旧宠刷新，永远不算成功。
            self.k_names.pop(slot, None)
            if self.pet_panel.get(slot) is not None:
                self.pet_panel[slot] = None
                self._push_pet_panel()
            return False
        old = self.pet_panel.get(slot)
        # 短包（partial）没有名字/等级/最大HP：沿用上一次长包解出来的值，
        # 只覆盖这次真正带过来的数值；满档标记也一并沿用。
        if old:
            if pet.get("level") is None:
                pet["level"] = old.get("level")
            if not pet.get("name"):
                pet["name"] = old.get("name")
                pet["base_name"] = old.get("base_name")
            if not pet.get("hp_max"):
                pet["hp_max"] = old.get("hp_max", 0)
            pet["full"] = old.get("full", False)

        if new_catch:
            # 满档判的是「生成出来的属性」，所以用 hp_max 而不是当前 hp
            hp_base = pet.get("hp_max") or pet.get("hp")
            pet["full"] = is_full_pet(pet.get("level"), hp_base,
                                      pet.get("atk"), pet.get("def"),
                                      pet.get("agi"))
            if pet["full"]:
                self.log("ok", f"  ★ 满档：{pet.get('name') or '宠物'}"
                               f" Lv{pet.get('level')}（{slot}）")
            else:
                self.log("dim", f"  新抓 {pet.get('name') or '宠物'}"
                                f" Lv{pet.get('level')} 非满档"
                                f"（hp{hp_base} atk{pet.get('atk')}"
                                f" def{pet.get('def')} agi{pet.get('agi')}）")
        self.pet_panel[slot] = pet
        self._push_pet_panel()
        return True

    # ------------------------------------------------------------------
    # 新抓宠资料上下文（时序修正方案 §5 / §6 / §9）
    # ------------------------------------------------------------------
    # 为什么必须和 catch_result_pending 分开：
    #   那个 flag 一到最终 BA/BE 就被关掉（战斗统计要闭环），可服务端的
    #   fid=46 **完整长包可能更晚才到**（实战常见 BT→BE→K长包、
    #   K短包→BE→K长包）。一旦跟着关掉，晚到的 K 只能按"普通宠物栏刷新"
    #   处理 —— 于是满档不判、非满档也不丢，界面上就表现为
    #   "抓到了，但既没 ★满档 也没丢弃"（2026-09-30 Lv96 巴朵兰恩）。
    #
    # 这份上下文只回答一个问题：**接下来哪个 K 槽是刚才抓到的那只宠。**
    # 它的生命周期由"认回与否"决定，不由战斗是否结束决定。

    def occupied_slots(self):
        """抓宠前已占用的槽 = 名字缓存 ∪ 宠物面板非空槽（文档 §6）。

        只看 k_names 是不够的：某个已有宠可能从头到尾只收到过短包，
        面板知道它"有宠"但名字还没同步过。那种槽必须算作已存在，
        否则会被误认成"抓宠后新出现的槽"。
        """
        out = set(self.k_names.keys())
        out |= {s for s in PET_SLOTS if self.pet_panel.get(s) is not None}
        return out

    def open_pend(self, target_name):
        """发起一次抓宠动作时打开新宠识别上下文。

        ⚠ 不无条件覆盖未完成的旧上下文：上一场可能已判定成功但还在等
        晚到的完整长包，直接覆盖会把那只宠永久漏掉（文档 §9）。
        只有旧上下文已经完成/确定无宠时才替换。
        """
        if self._pend is not None and not self._pend.get("done"):
            self.log("dim", f"  上一次抓宠仍在等待完整资料"
                            f"（{self._pend.get('target')}），本次先排队不覆盖")
            return self._pend
        self._pend = {
            "target": target_name,          # 本次捕捉目标名（防同名旧宠误命中）
            "before": self.occupied_slots(),  # 抓宠前已占用槽
            "cand": None,                   # 已观察到的候选新槽（短包也算）
            "full_done": False,             # 满档判定是否已做过（只做一次）
            "drop_done": False,             # 丢弃决策是否已做过（只做一次）
            "done": False,                  # 整体是否已完成
            "t": time.time(),
        }
        return self._pend

    def close_pend(self, why):
        """上下文完成或明确无宠 -> 清理。"""
        if self._pend is not None:
            self.log("dim", f"  新宠识别上下文结束（{why}）")
            self._pend = None

    def _bt_says_failed(self):
        """BT 是否**明确**回报这次捕捉没成功。

        只对 flag 下结论：实测 f1 = 捕捉成功的强推断，其余值（f0 等）
        才敢当"明确没抓到"。拿不准时返回 False —— 宁可让上下文多活一会，
        也绝不因为过早回收而漏掉晚到的 K 长包。
        """
        return self._bt_flag is not None and self._bt_flag != 1

    def match_pend_slot(self, slot, pet, name):
        """判断这条 fid=46 是不是"刚才抓到的那只宠"（文档 §7 第二层）。

        返回 (是否命中, 原因)。刻意**不看** catch_result_pending ——
        战斗已经 finish 也必须能认回来。
        """
        pend = self._pend
        if pend is None or pend.get("done"):
            return False, "没有活跃的新宠识别上下文"
        if slot in self._decided_new_slots:
            return False, "该槽已判定过新宠"
        if slot in pend["before"]:
            return False, f"{slot} 在抓宠前已占用（已有宠刷新）"
        if pend["cand"] is not None and slot != pend["cand"]:
            return False, f"候选槽已锁定为 {pend['cand']}"
        tgt = pend.get("target")
        # 完整包有名字就必须对得上；短包没名字，交给槽位判断
        if name is not None and tgt is not None and name != tgt:
            return False, f"名字 {name} != 本次目标 {tgt}"
        if pet is not None and pet.get("partial"):
            # 短包：够格当候选，但**不够格下结论**
            return True, "短包，仅记为候选槽"
        return True, "命中新宠"

    # ------------------------------------------------------------------
    # 丢弃宠物（丢弃宠物.MD）
    # ------------------------------------------------------------------
    def _enqueue_drop(self, slot, pet):
        """新抓到的非满档宠 -> 排队，等战斗结束（脱离战场）再丢。

        排队而不是当场发：战斗中角色坐标是"遇敌那一格"，服务端对战斗态
        的角色做丢弃大概率不认；等 BE/finish 之后回到 state9 再发更稳。
        """
        if slot not in PET_SLOTS or slot in self.drop_queue:
            return False
        if not self.catch_cfg.get("drop_non_full"):
            return False
        if not pet:
            return False                      # 空槽：绝不发
        if pet.get("full"):
            return False                      # 满档：留着
        if pet.get("partial") or pet.get("level") is None:
            # 短包（xZa）没有等级/最大HP，判不了满档 —— 拿不到确定结论
            # 就绝不丢，宁可留着也不能误丢用户的宠。
            self.log("dim", f"  {slot} 只有紧凑更新包，无法判定满档，不丢弃")
            return False
        self.drop_queue.append(slot)
        self.log("warn", f"  🗑 排队丢弃 {slot} "
                         f"{pet.get('name') or '宠物'} Lv{pet.get('level')}"
                         f"（非满档）")
        return True

    def _flush_drops(self):
        """把排队的槽位发出去（C>S fid=21）。

        ⚠ 三条铁律（文档 §1 / §2 / §4）：
          1. 只丢**有宠**的槽（pet_panel 里还是空的就取消）；
          2. 发完**不本地清空**，栏位以随后到来的 S>C fid=46 为准；
          3. 一次只处理一条，等 fid=46 回来再处理下一条，避免连丢刷屏。
        """
        if not self.drop_queue:
            return 0
        slot = self.drop_queue[0]
        pet = self.pet_panel.get(slot)
        if pet is None:
            self.drop_queue.pop(0)
            self.log("dim", f"  {slot} 已是空槽，取消丢弃")
            return 0
        try:
            s = self.g.snapshot()
        except Exception:
            return 0
        x, y = int(s.get("x") or 0), int(s.get("y") or 0)
        l2 = build_drop_l2(x, y, slot)
        if l2 is None:
            self.drop_queue.pop(0)
            return 0
        self.b.send(enc(fe.build_drop(x, y, slot, self.key)))
        self.drop_queue.pop(0)
        self.catch_stats["dropped"] += 1
        self.log("warn", f"  🗑 已发丢弃 fid=21  {l2}"
                         f"（{slot} {pet.get('name') or '宠物'} "
                         f"Lv{pet.get('level')}，等 fid=46 确认）")
        self._push_catch_stat()
        return 1

    # ===================================================================
    # 战后自动恢复 v1（文档 §39）
    #
    # 边界：这是「战斗外地图态动作」，不是战斗决策，所以放在 Engine，
    # stw_battle.py 一行都不改（文档 §63）。
    # 原则：非阻塞状态机 + 内存确认 + 与遇敌/丢宠互斥 + 任一失败不无限重试。
    # ===================================================================

    def _clear_recovery(self):
        """清空本场恢复上下文。

        ⚠ 绝不清 `_qi_scan_next_slot` / `_qi_known_slot`：
        那是整个 Engine 生命周期的全局背包扫描进度（文档 §11）。
        """
        self._recovery_pending = False
        self._recovery_state = "IDLE"
        self._recovery_deadline = 0.0
        self._recovery_before_qi = None
        self._recovery_before_hp = None
        self._recovery_target = None
        self._recovery_done_targets = set()
        self._recovery_reason = ""
        self._recovery_item_slot = None

    def _schedule_post_battle_recovery(self, reason):
        """战斗结束 -> 只「安排」恢复，实际推进交给主循环 tick（文档 §17/§18）。"""
        # 停止自动战斗后不再代发任何自动动作；程序退出前也不安排（文档 §61/§62）
        if self.stop_flag.is_set():
            return
        if not self.auto_ev.is_set():
            self.log("dim", "  战斗结束：自动执行已关闭，不做战后恢复")
            self._clear_recovery()
            return

        self._recovery_pending = True
        self._recovery_state = "WAIT_MAP"
        self._recovery_deadline = time.time() + RECOVERY_WAIT_MAP_TIMEOUT
        self._recovery_before_qi = None
        self._recovery_before_hp = None
        self._recovery_target = None
        self._recovery_done_targets = set()
        self._recovery_reason = reason
        self._recovery_item_slot = None
        self.log("sys", "  ♥ 已安排战后恢复，等待回到 state=9")

    def _read_u32(self, addr):
        """读一个 uint32（little-endian）。

        复用 ae.Game 已有的只读句柄（PROCESS_VM_READ|QUERY_INFORMATION），
        不额外 OpenProcess（文档 §10.4）。读失败一律抛异常，由恢复流程兜住。
        """
        raw = self.g.read_bytes(int(addr), 4)
        if raw is None or len(raw) != 4:
            raise RuntimeError(f"读取长度不对 @0x{int(addr):08X}")
        return int.from_bytes(raw, "little")

    def _read_recovery_stats(self):
        return {
            "player_hp": self._read_u32(PLAYER_HP_ADDR),
            "player_max_hp": self._read_u32(PLAYER_MAX_HP_ADDR),
            "qi": self._read_u32(PLAYER_QI_ADDR),
            "k0_hp": self._read_u32(K0_HP_ADDR),
            "k0_max_hp": self._read_u32(K0_MAX_HP_ADDR),
        }

    def _validate_recovery_stats(self, d):
        """地址失效后别读到垃圾值还猛发包（文档 §12）。只做基本合法性。"""
        if d["player_max_hp"] <= 0:
            return False
        if d["player_hp"] > d["player_max_hp"]:
            return False
        if d["k0_max_hp"] <= 0:
            return False
        if d["k0_hp"] > d["k0_max_hp"]:
            return False
        if d["qi"] > 100000:
            return False
        return True

    def _finish_recovery(self):
        self.log("ok", "  ♥ 战后恢复检查完成，恢复快速遇敌")
        self._clear_recovery()

    def _fail_recovery(self, why):
        """恢复失败 ≠ Engine 崩溃：记录 + 释放，原有功能继续（文档 §42/§52）。"""
        self.log("warn", f"  ⚠ 战后恢复中止：{why}")
        self._clear_recovery()

    def _request_global_break(self, reason):
        """2..15 全部走完仍无气力回复 -> 整个 Engine 主循环退出（文档 §12/§32.2）。"""
        self._global_break = True
        self._global_break_reason = reason
        self.log("warn", f"  ⚠ {reason}")
        self._clear_recovery()

    def _next_qi_item_slot(self):
        """已知有效槽位优先复用；否则从全局游标继续（文档 §30.3）。"""
        if self._qi_known_slot is not None:
            return self._qi_known_slot
        if self._qi_scan_next_slot > QI_ITEM_SLOT_MAX:
            return None
        return self._qi_scan_next_slot

    def _send_qi_item_attempt(self, snap, qi_before):
        """发一次 fid=17 试探当前槽位，然后等气力是否真涨（文档 §31/§43.2）。"""
        slot = self._next_qi_item_slot()
        if slot is None:
            self._request_global_break(
                "气力<=30，背包格2至15全局扫描已耗尽，"
                "未找到可使气力上涨的道具")
            return

        x = int(snap.get("x") or 0)
        y = int(snap.get("y") or 0)
        # ⚠ 坐标必须每次取最新：字段0/1 参与 checksum，用旧坐标服务器不认
        l2 = build_use_item_l2(x, y, slot, ITEM_TARGET_SELF, self.key)
        self.b.send(enc(l2))

        self._recovery_item_slot = slot
        self._recovery_before_qi = int(qi_before)
        self._recovery_deadline = time.time() + RECOVERY_ACTION_TIMEOUT
        self._recovery_state = "WAIT_QI"
        self.log("sys", f"  ♢ 尝试背包格 {slot}，"
                        f"known={self._qi_known_slot} "
                        f"next={self._qi_scan_next_slot}")

    def _send_recovery_heal(self, snap, target, hp_before):
        """fid=57 精灵[1] 治疗一个对象（文档 §34/§44）。"""
        if target == "player":
            proto_target = HEAL_TARGET_PLAYER
            shown = "角色"
        elif target == "k0":
            proto_target = HEAL_TARGET_K0
            shown = "K0骑宠"
            if proto_target is None:
                # target 尚未抓包确认 —— 绝不发猜测包
                self.log("warn", "  ⚠ K0 精灵治疗 target 尚未抓包确认，跳过 K0")
                self._recovery_done_targets.add("k0")
                self._recovery_state = "CHECK"
                return
        else:
            self._fail_recovery(f"未知恢复目标 {target}")
            return

        x = int(snap.get("x") or 0)
        y = int(snap.get("y") or 0)
        l2 = build_use_spirit_l2(x, y, HEAL_SKILL_SLOT, proto_target, self.key)
        self.b.send(enc(l2))

        self._recovery_target = target
        self._recovery_before_hp = hp_before
        self._recovery_deadline = time.time() + RECOVERY_ACTION_TIMEOUT
        self._recovery_state = "WAIT_HEAL"
        self.log("sys", f"  ♥ {shown} 缺血超过 {POST_HEAL_MISSING_HP}，"
                        f"使用精灵[{HEAL_SKILL_SLOT}]")

    def _post_battle_recovery_tick(self, snap):
        """推进一次恢复状态机（文档 §45）。

        返回 True：本 tick 恢复仍占用地图动作 -> 禁止遇敌 / 丢宠 / hazard。
        返回 False：没有恢复任务（或本场已结束/失败）。
        """
        if not self._recovery_pending:
            return False

        # 恢复途中用户点停止 -> 立即取消，不再发任何动作（文档 §61）
        if not self.auto_ev.is_set():
            self.log("dim", "  自动执行已关闭，取消战后恢复")
            self._clear_recovery()
            return False

        now = time.time()

        # ---------------- WAIT_MAP ----------------
        if self._recovery_state == "WAIT_MAP":
            if snap.get("state") != 9:
                if now > self._recovery_deadline:
                    self._fail_recovery("战斗结束后等待 state=9 超时")
                    return False
                return True
            self.log("dim", "  已回到 state=9，开始读取战后 HP / 气力")
            self._recovery_state = "CHECK"

        # ---------------- WAIT_QI ----------------
        if self._recovery_state == "WAIT_QI":
            try:
                qi_now = self._read_u32(PLAYER_QI_ADDR)
            except Exception as e:
                self._fail_recovery(f"读取气力失败：{e}")
                return False

            before_qi = int(self._recovery_before_qi or 0)

            if qi_now > before_qi:
                slot = self._recovery_item_slot
                self._qi_known_slot = slot
                if self._qi_scan_next_slot <= slot:
                    self._qi_scan_next_slot = slot + 1
                self.log("ok", f"  ✓ 背包格 {slot} 气力回复生效："
                               f"{before_qi} → {qi_now}；记为全局有效槽")
                self._recovery_item_slot = None
                self._recovery_before_qi = None
                self._recovery_state = "CHECK"

            elif now > self._recovery_deadline:
                failed_slot = self._recovery_item_slot
                self.log("dim", f"  背包格 {failed_slot} 未检测到气力上涨"
                                f" → 全局推进")
                if self._qi_known_slot == failed_slot:
                    # 之前有效的那格现在耗尽/失效
                    self._qi_known_slot = None
                else:
                    # 永久跳过这一格，以后任何场次都不再尝试
                    self._qi_scan_next_slot = max(
                        self._qi_scan_next_slot, int(failed_slot) + 1)
                self._recovery_item_slot = None
                self._recovery_before_qi = qi_now
                self._send_qi_item_attempt(snap, qi_now)
                if self._global_break:
                    return False
                return True

            else:
                return True

        # ---------------- WAIT_HEAL ----------------
        if self._recovery_state == "WAIT_HEAL":
            try:
                if self._recovery_target == "player":
                    hp_now = self._read_u32(PLAYER_HP_ADDR)
                elif self._recovery_target == "k0":
                    hp_now = self._read_u32(K0_HP_ADDR)
                else:
                    self._fail_recovery("WAIT_HEAL 没有合法 target")
                    return False
            except Exception as e:
                self._fail_recovery(f"读取治疗结果失败：{e}")
                return False

            if hp_now > int(self._recovery_before_hp or 0):
                target = self._recovery_target
                self.log("ok", f"  ✓ {'角色' if target == 'player' else 'K0骑宠'}"
                               f"治疗生效：{self._recovery_before_hp} → {hp_now}")
                # 每对象每场最多一次，防止回血不够 -> 无限重复治疗（文档 §15）
                self._recovery_done_targets.add(target)
                self._recovery_target = None
                self._recovery_before_hp = None
                self._recovery_state = "CHECK"
            elif now > self._recovery_deadline:
                self._fail_recovery(
                    f"{self._recovery_target} 使用精灵后 HP 未上涨")
                return False
            else:
                return True

        # ---------------- CHECK ----------------
        if self._recovery_state == "CHECK":
            try:
                d = self._read_recovery_stats()
            except Exception as e:
                self._fail_recovery(f"读取战后状态失败：{e}")
                return False

            if not self._validate_recovery_stats(d):
                self._fail_recovery(f"内存数据不合法：{d}")
                return False

            player_missing = d["player_max_hp"] - d["player_hp"]
            k0_missing = d["k0_max_hp"] - d["k0_hp"]
            self.log("dim", f"  战后状态：角色 {d['player_hp']}/"
                            f"{d['player_max_hp']}（缺 {player_missing}） · "
                            f"K0 {d['k0_hp']}/{d['k0_max_hp']}"
                            f"（缺 {k0_missing}） · 气力 {d['qi']}")

            target = None
            hp_before = None
            # 严格：missing 必须 > 300（恰好 300 不治疗），角色优先（文档 §26/§27）
            if ("player" not in self._recovery_done_targets
                    and player_missing > POST_HEAL_MISSING_HP):
                target = "player"
                hp_before = d["player_hp"]
            elif ("k0" not in self._recovery_done_targets
                    and k0_missing > POST_HEAL_MISSING_HP):
                target = "k0"
                hp_before = d["k0_hp"]

            if target is None:
                self._finish_recovery()
                return False

            # 每次治疗前都重新判断气力：治完角色可能把气力打下去（文档 §28/§29）
            if d["qi"] <= QI_DIRECT_HEAL_MIN:
                self._send_qi_item_attempt(snap, d["qi"])
                if self._global_break:
                    return False
                return True

            self._send_recovery_heal(snap, target, hp_before)
            return True

        # 未知 state：安全失败，绝不卡住主循环（文档 §53）
        self._fail_recovery(f"未知恢复状态 {self._recovery_state}")
        return False

    def _push_catch_stat(self):
        """把抓宠统计推给界面（界面只显示，不参与协议判定）。"""
        d = dict(self.catch_stats)
        d["mode"] = self.cfg.get("mode")
        self.q.put(("catch_stat", d))

    def _resolve_catch(self, bt_seen, k_seen, k_name, target_gone,
                       force_unknown=False):
        """综合 BT / Kx / BC 三处证据判定一次捕捉结果。

        成功证据：
            K 新槽更新 and (BT 命中 or 目标已从 BC 消失)

        这里故意不在 BT 一到就立刻记 unknown。服务器包顺序可能是
        BT -> K，也可能是 K -> BT；过早记 unknown 会把随后到来的成功
        证据漏掉。只有调用方明确 force_unknown=True（通常是下一次 BA
        操作窗口或战斗结束）时，才把仍未闭环的尝试记为“待确认”。

        返回 "success" / "unknown" / None。
        """
        if k_seen and (bt_seen or target_gone):
            self.catch_stats["successes"] += 1
            shown = k_name or "新宠物"
            self.log("ok", f"  ✔ 捕捉成功：{shown}"
                           f"（BT={'有' if bt_seen else '无'}，"
                           f"K={'有' if k_seen else '无'}，"
                           f"目标已离场={'是' if target_gone else '否'}）")
            self.q.put(("log", "battle", f"捕捉成功：{shown}"))

            # 达到停止条件时，不直接掐断线程；如果本场还有敌人，
            # 下一 BA 操作窗口会先发逃跑，收到 BE/finish 后再停。
            after = self.catch_cfg.get("after_success", "continue")
            try:
                n = max(1, int(self.catch_cfg.get("stop_count") or 1))
            except (TypeError, ValueError):
                n = 1
            if after == "stop" or (after == "count"
                                   and self.catch_stats["successes"] >= n):
                self.catch_stop = True
                self.log("ok", f"  已达停止条件（{after}"
                               f"{'/' + str(n) if after == 'count' else ''}），"
                               "将在本场安全收尾后停止")
            return "success"

        if force_unknown:
            self.catch_stats["unknown"] += 1
            self.log("dim", "  ？捕捉结果待确认（本次尝试未形成完整成功证据）")
            return "unknown"

        return None

    def setup(self):
        self.pid = self.cfg["pid"]
        self.log("sys", f"正在附加 PID={self.pid} …")
        self.sess = frida.attach(self.pid)
        self.sn = frida.attach(self.pid)
        self.snc = self.sn.create_script(AGENT)
        self.snc.load()
        self.api = self.snc.exports_sync
        self.hook_sc = None
        self.key = sa.make_l2_key(self.cfg["account"])
        self.g = ae.Game(self.pid)
        self.b = sa.FridaSocketBridge(self.pid, 9065)
        self.log("sys", "已挂载抓包，正在等待网桥 latch 到 9065 端口…")
        st = self.b.status()
        w = 0.0
        while not st.get("ready") and w < 90 and not self.stop_flag.is_set():
            time.sleep(2.0)
            w += 2.0
            st = self.b.status()
            self.log("sys", f"  等待网桥就绪 {w:.0f}s …")
        if not st.get("ready"):
            raise RuntimeError("网桥未就绪（游戏发包太稀疏），请稍后重试")
        self.log("sys", f"PID={self.pid}  socket={st.get('socket')}  已连接")

    def set_hook(self, on):
        if on == self.hook_on:
            return
        if on:
            self.hook_sc = self.sess.create_script(HOOK)
            self.hook_sc.load()
            self.log("sys", "已挂载跳过战斗界面钩子（set_state(10)→9）")
        else:
            if self.hook_sc:
                self.hook_sc.unload()
                self.hook_sc = None
            self.log("sys", "已卸载钩子，游戏将正常进入战斗界面")
        self.hook_on = on

    def teardown(self):
        try:
            self.set_hook(False)
        except Exception:
            pass
        try:
            self.snc.unload()
        except Exception:
            pass
        for s in ("sn", "sess"):
            try:
                getattr(self, s).detach()
            except Exception:
                pass
        for o in ("b", "g"):
            try:
                getattr(self, o).close()
            except Exception:
                pass

    # ---- 用真实报文校验扫出来的账号对不对 ----
    def try_verify(self, frame):
        """fid=42 的第一个字段用正确 key 解出来应是可打印 ASCII（如 2IP）。"""
        for acc in self.cfg.get("accounts") or [self.cfg["account"]]:
            try:
                l2 = sa.decode_layer1(frame)
                p = l2.split(b";")
                if len(p) < 3:
                    continue
                v = sa.destring(p[2], sa.make_l2_key(acc))
                if not v:
                    continue
                if all(32 <= c < 127 for c in v):
                    if acc != self.cfg["account"]:
                        self.cfg["account"] = acc
                        self.key = sa.make_l2_key(acc)
                        self.log("warn", f"账号自动校正为 {acc}（解密校验通过）"
                                         f"——后续收包/战斗/走路/结束全部改用新 key")
                        # Engine.cfg 是开跑前快照的副本，不推消息界面还显示旧账号
                        accs = list(self.cfg.get("accounts") or [])
                        if acc not in accs:
                            accs.insert(0, acc)
                            self.cfg["accounts"] = accs
                        self.q.put(("account", (acc, accs)))
                    else:
                        self.log("sys", f"账号 {acc} 解密校验通过")
                    return True
            except Exception:
                continue
        return False

    def run(self):
        try:
            self.setup()
        except Exception as e:
            self.q.put(("fatal", str(e)))
            return
        # 监听从这一刻起就在线（与「是否自动执行」无关）
        self.battle_hook_active = True
        self.log("sys", "战斗监听已挂载：开始接收/解析战斗包"
                        "（未点「开始自动战斗」前不会代发任何指令）")
        self.q.put(("hook_state", True))
        # ⚠ 这里绝不许把 self.key 缓存成局部变量 key。
        # try_verify() 一旦用真实报文把账号校正过来，只会改 self.key；
        # 缓存的局部变量不会跟着变，于是后续「收包解密 / 战斗 fid=14 /
        # 走路 fid=1 / 结束 fid=8」全部继续用旧 key，界面却显示"已校正"。
        # 所以运行时一律读 self.key，fid=8 也在发送时才现编。
        fh = open(LOG, "w", encoding="utf-8")

        # 战斗状态机（v2.2 §7）：决策全在它里面，Engine 只管「怎么发」。
        # resolve_catch 晚绑定成闭包：它要动 Engine 的 catch_stats / _pend。
        self.bs = BattleSession(
            self.cfg, self.catch_cfg, log=self.log,
            resolve_catch=lambda force: resolve_catch_if_ready(force))

        s = self.g.snapshot()
        HOME = (s["x"], s["y"])
        MID = s["map"]
        MI = md.load(MID)
        AXIS = md.pick_axis(MI, *HOME) if MI else ("c", "g")
        if MI:
            self.log("sys", f"地图 {MID} {MI.w}x{MI.h}  站立格 {MI.describe(*HOME)}")
            if AXIS:
                self.log("sys", f"摆动轴 {AXIS}（落点锁在 HOME ± {md.DIRS[AXIS[0]]}）")
            else:
                # 某些大地图/特殊落点找不到一对“双向都安全”的摆动轴。
                # 旧代码这里直接访问 AXIS[0]，导致 Engine 线程 TypeError 退出，
                # 后续一个 fid=1 遇敌包都不会再发。保持 AXIS=None，主循环走
                # 已有 gc/cg 通用回退，并在每次走位前继续尝试恢复安全轴。
                self.log("warn", "当前格找不到双向安全摆动轴，先用通用 gc/cg 走位；"
                                 "移动后会自动重试安全轴")
        else:
            self.log("warn", f"找不到 {MID}.MAP，无地形保护")
        self.log("sys", f"起始格 {HOME}")

        t0 = time.time()
        last_walk = 0.0
        in_battle = False
        battle_t0 = 0.0
        battles = rounds = walks = hazard = 0
        drove = False            # 本场的 fid=14 是不是我们代发的
        sent14 = 0
        last_act_t = 0.0         # 上次代发 fid=14 的时刻（兜底计时用）
        stall_warned = False     # 超时告警只打一次，别每 0.15s 刷屏
        # —— 抓宠跟踪里唯一留在 Engine 的量：K 槽快照 ——
        # 它属于 K包认回（v2.2 §8 明确第二批再搬），所以留在这里
        catch_k_before = set()   # 本次尝试前已经存在/已知的 K 槽
        # 其余战斗状态（round_inflight / victory_pending / last_units /
        # 抓宠跟踪 / 上毒状态机）全部在 self.bs（stw_battle.BattleSession）
        fid_in = {}
        paused_until = 0.0
        player_name = None
        verified = False
        prev_auto = False               # 停止流程靠「auto 下降沿」触发

        def send_end8():
            """战斗结束确认 fid=8 —— 发送时才编码，用当前 self.key。

            不能在启动时预编码成常量：账号自动校正后 key 会变，
            预编码的字节流是旧 key 加密的，服务器解不开。
            """
            msg = (b"&;8;" + sa.enint(0, self.key) + b";"
                   + sa.enint(0, self.key) + b";#;")
            self.b.send(enc(msg))

        def finish(reason):
            """只有我们代发过 fid=14 才需要补 fid=8，否则服务器一直锁着角色。

            中途取消勾选「快速战斗」也必须补，不然角色卡在战斗里出不来。
            收尾时把所有战斗状态一起清掉，别把上一场的胜利状态带进下一场。
            """
            nonlocal in_battle, drove
            was_in_battle = bool(in_battle)
            if in_battle and drove:
                send_end8()
                drove = False
                self.log("ok", f"  补发 fid=8 战斗结束确认（{reason}）")
                time.sleep(1.0)
            in_battle = False
            self.bs.finish_battle()
            # 战后恢复统一在这里「安排」，不在各 BE 分支复制五份；
            # 真正的治疗由主循环 tick 推进（文档 §16/§17）。
            if was_in_battle:
                self._schedule_post_battle_recovery(reason)

        def resolve_catch_if_ready(force_unknown=False):
            """按当前已收到的 BT / K / BC 证据，最多结算本次捕捉一次。"""
            bs = self.bs
            if not bs.catch_result_pending or bs.catch_result_resolved:
                return None
            target_gone = (
                bs.last_catch_target is not None
                and bs.last_catch_target not in alive_enemy_slots(bs.last_units)
            )
            result = self._resolve_catch(
                bs.catch_bt_seen, bs.catch_k_seen, bs.catch_k_name,
                target_gone, force_unknown=force_unknown)
            if result:
                bs.catch_result_resolved = True
                bs.catch_result_pending = False
                # ⚠ 战斗统计闭环 ≠ 新宠资料闭环：这里**不能**因为战斗统计
                #   结算掉就关 _pend。
                #   "unknown" 恰恰表示"证据不足、没结论" —— 这正是最需要
                #   继续等 K 长包的场景（BT→BE→K晚到 就属于这一种），
                #   关掉它正好会重现"既没满档标记、也没丢弃"的故障。
                #   文档 §9 的"明确失败才清理"在这里只有一种可靠情形：
                #   BT 明确回报捕捉未成功（BT flag 判失败）且从未出现过
                #   候选新槽 —— 那才说明确实没有新宠。
                if result == "unknown" and self._pend is not None \
                        and not self._pend.get("done") \
                        and self._pend.get("cand") is None \
                        and bs.catch_bt_seen and not bs.catch_k_seen \
                        and self._bt_says_failed():
                    self.close_pend("BT 明确捕捉未成功且无候选新槽")
                self._push_catch_stat()
            return result

        def exec_cmd(cmd):
            """把 BattleSession 的决策发出去 —— Battle 只管「做什么」。

            ⚠ 一次机会 = 两条 fid=14（角色 + 战宠），build_round() 已保证；
            只发一条服务器会一直等另一个单位，本回合永远不结算。
            返回 True 表示真的发了。
            """
            nonlocal sent14, rounds, drove, last_act_t, catch_k_before
            if cmd is None:
                return False

            # ------------------------------------------------------------
            # 1. 先消费 Battle -> Engine 的统计副作用
            #    ⚠ 必须在 kind 早退**之前**：_no_match() 的 silent 分支返回
            #    Command("none")，它不是 fid14，但 no_match 仍要 +1。
            # ------------------------------------------------------------
            stat_changed = False
            if cmd.hpmax_matched:
                self.catch_stats["hpmax_matched"] += 1
                stat_changed = True
                if cmd.target is None:
                    self.log("dim", "  [统计] HPmax命中 +1")
                else:
                    self.log("dim", f"  [统计] HPmax命中 +1："
                                    f"敌[0x{cmd.target:X}] {cmd.name or ''}")
            if cmd.poison_confirmed:
                self.catch_stats["poison_confirmed"] += 1
                stat_changed = True
                self.log("ok", "  [统计] 毒伤确认 +1：" +
                               (f"敌[0x{cmd.target:X}]"
                                if cmd.target is not None else "（无目标）"))
            if cmd.no_match:
                self.catch_stats["no_match"] += 1
                stat_changed = True
                self.log("dim", "  [统计] 未命中 +1")

            # ------------------------------------------------------------
            # 2. 非 fid14 不发包，但上面的统计副作用仍然有效
            # ------------------------------------------------------------
            if cmd.kind != "fid14":
                if stat_changed:
                    self._push_catch_stat()
                return False

            for c in cmd.lines:
                self.b.send(enc(fe.build_battle_cmd(c, self.key)))
            sent14 += len(cmd.lines)
            rounds += 1
            drove = True
            last_act_t = time.time()
            self.bs.mark_sent(cmd)
            self.q.put(("log", "battle", f"第 {battles} 场 · 第 {rounds} 回合"))
            if cmd.target is None:
                self.q.put(("log", "battle", f"我方行动：{cmd.mode}"))
                self.log("act", f"  ▶ 回合 {rounds}：{cmd.mode}"
                                f"（{cmd.why} · {' '.join(cmd.lines)}）")
            else:
                self.q.put(("log", "battle",
                            f"我方行动：{cmd.mode} → 敌[0x{cmd.target:X}]"))
                self.log("act", f"  ▶ 回合 {rounds}：{cmd.mode} → "
                                f"敌[0x{cmd.target:X}]"
                                f"（{cmd.why} · {' '.join(cmd.lines)}）")
            if cmd.attempt:
                # K 侧成功证据只认「本次尝试后新出现的 K 槽」：服务器会反复
                # 刷新已有 K1/K2，只按同名判断会把旧宠刷新误认成新捕获。
                catch_k_before = set(self.k_names.keys())
                self._bt_flag = None
                self.open_pend(cmd.name)
                self.catch_stats["attempts"] += 1
                stat_changed = True
            if stat_changed:
                self._push_catch_stat()
            return True

        def on_window(rnd):
            """处理一个 BA low=0 操作窗口（真正代发 fid=14 的唯一入口）。

            决策向 BattleSession 要（v2.2 §9：Battle 负责「我要做什么」），
            这里只负责把它发出去 + 记日志 / 推统计。

            抽成函数而不是写死在 BA 分支里，是因为「监听」和「执行」已经解耦：
            只监听状态下收到的 BA low=0 不能丢——用户点「开始自动战斗」时
            服务器通常已经在等指令，不会再补发第二个 BA。记住窗口（
            bs.pending_window），auto 置位后由主循环补调用一次，这一点对应
            文档 §9「不要重新 Hook、不要清空状态，但要允许处理当前窗口」。
            """
            nonlocal stall_warned, last_walk
            stall_warned = False
            cmd = self.bs.decide_action(rnd=rnd, rounds=rounds,
                                        catch_stop=self.catch_stop)
            if cmd.kind == "victory":
                # 胜利：服务器不发 BE，只给这个 BA low=0 —— 不发任何
                # fid=14，只补 fid=8 解锁（战斗统计已在 decide 里结算过）
                dt = time.time() - battle_t0
                self.q.put(("log", "battle",
                            f"战斗胜利 · {dt:.1f}s · {rounds} 回合"))
                self.log("ok", f"  ✔ 敌方全灭，收到最终 BA low=0"
                               f"（{dt:.1f}s，{rounds} 回合）")
                finish("敌方全灭")
                last_walk = time.time()
                return
            # 统计变化 -> 推 UI 已经统一收进 exec_cmd()（副作用在 kind 早退
            # 之前就消费了），这里不再重复 push，否则 no_match 会双计。
            exec_cmd(cmd)

        try:
            while not self.stop_flag.is_set():
                now = time.time() - t0
                # 自动执行开关：不置位就只监听、不代发（文档 §7）
                auto = self.auto_ev.is_set()
                if auto:
                    self._wait_logged = False
                # ---- 停止流程状态机的两个边沿 ----
                # 只在这里切换，运行循环一行都不改（文档 §10）
                if auto and self.stop_phase != STOP_RUNNING:
                    self.map_sync_score = 0
                    self.map_sync_ready_at = 0.0
                    self._set_stop_phase(STOP_RUNNING, "")
                elif not auto and prev_auto:
                    # 用户点了「停止自动战斗」：
                    # 只停发动作 —— 不清战斗状态、不关 Hook、不强制 fid=8
                    self._set_stop_phase(STOP_PENDING, "")
                    self.log("sys", "■ 已停止自动战斗：等待当前战斗自然结束"
                                    "（不清状态 / 不关监听 / 不强制 fid=8）")
                prev_auto = auto
                # 时长/场数上限只在「自动执行」时生效；
                # 否则纯监听 30 分钟后监听就自己断了，不合理。
                # ⚠ 上限命中必须打日志：早期这里是裸 break，跑到点就静默退出，
                #   日志只留「已卸载钩子 + 结束汇总」，和崩溃/手动停止分不出来
                #   （2026-10-01 晚那次 30 分钟自动收尾就是这么被误判的）。
                #   另注意 now 从**引擎挂载**起算，不是从点「开始自动战斗」起算。
                # 战后恢复没做完就不要抢着退出，否则最后一场不回血（文档 §25）
                if auto and not self._recovery_pending:
                    if now > self.cfg["secs"]:
                        self.log("sys", f"■ 已达时长上限 {self.cfg['secs']:.0f}s"
                                        f"（引擎已跑 {now:.0f}s / {battles} 场）"
                                        " → 本场安全收尾后停止")
                        break
                    if battles >= self.cfg["maxb"]:
                        self.log("sys", f"■ 已达场数上限 {self.cfg['maxb']} 场"
                                        f"（引擎已跑 {now:.0f}s）"
                                        " → 本场安全收尾后停止")
                        break
                # 点「开始自动战斗」时补执行只监听期间等到的那个操作窗口。
                # 不重新 Hook、不清战斗状态，只是把积压的窗口用掉（文档 §9）。
                if auto and self.bs.pending_window and in_battle \
                        and self.cfg["fast_battle"]:
                    self.log("dim", "  补执行：监听期间积压的 BA low=0 操作窗口")
                    on_window(self.bs.pending_window_rnd)
                # 丢弃排队（丢弃宠物.MD）：回到地图才发，战斗态发了服务端不认。
                # 放在「抓到 N 只后停止」之前 —— 否则一 clear(auto) 就再没机会丢，
                # 抓宠流程结束时栏位里会留着一只本该丢掉的非满档宠。
                # 这里不看 auto：丢弃是用户勾选「丢弃不满档」时已授权的收尾动作。
                # 但必须让位给战后恢复：同一 tick 同时发 fid=21 和 fid=17/57
                # 会制造地图动作时序竞争（文档 §23）
                if self.drop_queue and not in_battle \
                        and not self._recovery_pending:
                    self._flush_drops()
                # 「抓到 N 只后停止」：只在战斗外停，别把角色锁在战场里；
                # 同样要等恢复做完再停，否则恢复会被 auto_ev.clear() 取消（§24）
                if self.catch_stop and not in_battle \
                        and not self._recovery_pending:
                    self.log("ok", "已达成抓宠目标，停止自动战斗")
                    self.auto_ev.clear()
                    self.q.put(("auto_state", False))
                    self.catch_stop = False
                # 跳过战斗界面的钩子仍然由「快速战斗」勾选决定：
                # 监听永远在线，但没勾选时用户要能看见战斗界面自己打
                self.set_hook(self.cfg["fast_battle"])

                for r in self.api.dump():
                    raw = bytes.fromhex(r["hex"])
                    frames = [f + b"\n" for f in raw.split(b"\n") if f.strip()] or [raw]
                    for fr in frames:
                        try:
                            l2 = sa.decode_layer1(fr)
                        except Exception:
                            continue
                        if not l2:
                            continue
                        p = l2.split(b";")
                        if len(p) < 2:
                            continue
                        fid = p[1].decode("latin1", "replace")
                        try:
                            v = sa.destring(p[2], self.key).decode("gb18030", "replace") \
                                if len(p) > 2 else ""
                        except Exception:
                            v = ""
                        fh.write(json.dumps({"t": round(now, 3), "dir": r["dir"],
                                             "fid": fid, "s": v}, ensure_ascii=False) + "\n")
                        if r["dir"] != "IN":
                            continue
                        fid_in[fid] = fid_in.get(fid, 0) + 1
                        # 停止流程：地图/NPC 刷新证据（文档 §5）
                        if self.stop_phase == MAP_SYNC_WAIT \
                                and fid in MAP_SYNC_FIDS:
                            self.map_sync_score += 1
                            self.log("dim", f"  地图同步包 fid={fid}"
                                            f"（{self.map_sync_score}/"
                                            f"{MAP_SYNC_SCORE_NEED}）{v[:48]}")
                            self._set_stop_phase(
                                MAP_SYNC_WAIT,
                                f"{self.map_sync_score}/{MAP_SYNC_SCORE_NEED}")
                        f = v.split("|")

                        # 开跑后先用真实报文校验一次账号
                        if not verified and fid == "42":
                            verified = self.try_verify(fr)

                        if fid == "43":
                            hazard += 1
                            if hazard == 1:
                                self.log("warn", "fid=43 遇敌动画洪水，熔断 1s")
                                paused_until = time.time() + 1.0
                            continue
                        if fid == "88":
                            continue
                        if fid == "7":
                            if not in_battle:
                                battles += 1
                                rounds = 0
                                self.q.put(("log", "battle", f"第 {battles} 场 · 等待队伍数据"))
                                self.q.put(("log", "battle", "正在初始化战斗…"))
                                in_battle = True
                                battle_t0 = time.time()
                                self.log("battle", f"⚔ 第 {battles} 场 · 遇敌")
                                last_act_t = 0.0
                                stall_warned = False
                                catch_k_before = set(self.k_names.keys())
                                # 战斗状态机整场重置（v2.2 §7）：round_inflight /
                                # victory_pending / last_units / 抓宠跟踪 /
                                # 上毒状态机全在 BattleSession 里，pexcluded 是
                                # "本场排除"，上一场验证失败的槽不带进新的一场
                                self.bs.reset_battle()
                                if self.cfg["fast_battle"]:
                                    # 接管这场战斗：战斗界面被跳过了，结束时必须补
                                    # fid=8，哪怕一次 BA 机会都没等到（否则角色卡住）
                                    drove = True
                                    # 不再在 fid=7 上抢先发指令：那时还不知道谁活着、
                                    # 该打哪个槽位，硬发 H|F / W|1|F 会打尸体。
                                    # 改成等服务器用 BA low==0 开出操作机会再发。
                                    self.q.put(("log", "battle",
                                                "等待操作机会（BA low=0）…"))
                                    self.log("dim", "  等待 BA 开出操作机会")
                                else:
                                    self.log("dim", "  旁观模式：等待你在游戏里操作")
                            continue
                        if fid == "15":
                            tag = f[0] if f else ""
                            # 组队服务器会把多个战斗段拼成一个 fid=15。
                            # 例如逃跑结算：BH|...|BE|...|BY|...，如果只看
                            # f[0]==BH 就会漏掉 BE，角色本地一直保持 in_battle，
                            # 直到 6s 告警 / 40s 兜底才恢复遇敌。
                            embedded_be = tag != "BE" and fid15_has_tag(v, "BE")
                            embedded_bt = tag != "BT" and fid15_has_tag(v, "BT")
                            if tag == "BC":
                                units = parse_bc(f[1:])
                                for tok in f[1:]:
                                    if _is_name(tok):
                                        player_name = tok
                                        break
                                self.q.put(("battle_units", (units, player_name)))
                                alive, victory = self.bs.on_bc(units, in_battle)
                                atxt = " ".join(f"{s:X}" for s in alive) or "无"
                                self.log("dim", f"  队伍数据已更新：{len(units)} 个单位"
                                                f"（存活敌方槽：{atxt}）")
                                # 胜利判定：杀光敌人时服务器不发 BE，只在 BC 里把
                                # 所有敌方 hp 抹成 0，然后给一个 BA low=0。必须
                                # 「本场确实见过敌人」才算 —— 这条由 BattleSession 判
                                if victory:
                                    self.log("ok", "  ✔ BC 确认敌方全部倒下，"
                                                   "等待服务器最终 BA")
                                # 抓宠模式：把「为什么抓 / 为什么不抓」推给界面，
                                # 实测时一眼能看出筛选条件哪里没命中
                                if self.cfg.get("mode") == "catch":
                                    self.q.put(("catch_match",
                                                catch_match_report(
                                                    units,
                                                    self.catch_cfg.get("rules")
                                                    or {})))
                                    # BT/K/BC 到达顺序并不保证固定；BC 更新后再尝试
                                    # 闭环一次，避免 BT 先到、K 后到时漏判成功。
                                    resolve_catch_if_ready(False)
                            elif tag == "BP":
                                self.q.put(("log", "battle", f"战场信息：{' · '.join(f[1:])}"))
                                self.log("dim", f"  战场信息 BP {'|'.join(f[1:])}")
                            elif tag == "BA":
                                ba = parse_ba(f[1:])
                                if ba is None:
                                    self.log("dim", f"  行动 BA {'|'.join(f[1:])}")
                                    continue
                                _val, low, rnd = ba
                                if not in_battle or not self.cfg["fast_battle"]:
                                    self.log("dim", f"  BA low=0x{low:X}（不代发）")
                                    continue
                                # 胜利判定先走：它属于「状态维护」，不是代打指令。
                                # 只监听时也要认账，否则战斗会一直挂着等 40s 兜底。
                                # （finish 只补 fid=8 解锁，不发任何 fid=14）
                                if self.bs.victory_pending:
                                    on_window(rnd)
                                    continue
                                if not auto:
                                    # 监听在线但还没开自动：状态照常维护，
                                    # 只是不发 fid=14（文档 §7）。
                                    # 先把这个窗口记住，点「开始自动战斗」后
                                    # 由主循环补一次执行——那时服务器已经在等
                                    # 指令，不会再补发第二个 BA low=0。
                                    self.bs.on_ba(low, rnd)
                                    if not self._wait_logged:
                                        self._wait_logged = True
                                        self.log("dim",
                                                 f"  BA low=0x{low:X} 已收到，"
                                                 "等待【开始自动战斗】"
                                                 "（当前只监听，不代发任何指令）")
                                    continue
                                if low != BA_ACT:
                                    # 非零 = 服务器 ACK / 行动完成位图，只观察不发
                                    self.log("dim",
                                             f"  BA low=0x{low:X} ACK"
                                             f"（角色{'✓' if low & BA_BIT_CHAR else '✗'}"
                                             f" 宠物{'✓' if low & BA_BIT_PET else '✗'}）")
                                    continue
                                on_window(rnd)
                                continue
                            elif tag == "BT":
                                # 🔥 抓宠结算包：必须和 BH/BJ 一样解除 inflight，
                                # 否则下一回合的合法 BA low=0 会被当重复窗口丢掉
                                # （双目标样本：抓掉 F 后还有 BA|10000|1 要处理 10）
                                stall_warned = False
                                bt = parse_bt(v)
                                if bt:
                                    if self.bs.on_bt(bt):
                                        self._bt_flag = bt["flag"]
                                    self.q.put(("log", "battle",
                                                f"捕捉结算：敌[0x{bt['target']:X}] "
                                                f"flag={bt['flag']}"))
                                    self.log("hit", f"  🎯 BT 捕捉结算 "
                                                    f"actor={bt['actor']:X} "
                                                    f"target={bt['target']:X} "
                                                    f"flag={bt['flag']}")
                                    # 不在这里强制 unknown：K 可能稍后才到。
                                    resolve_catch_if_ready(False)
                                else:
                                    self.log("dim", f"  BT {v[:80]}")
                                self._push_catch_stat()
                            elif tag in ("BH", "BJ", "BY"):
                                # 🔥 结算包解除 inflight。组队实测还会以 BY 开头，
                                # 且同一包内继续拼 BT/BH/BE，所以 BY 也必须认。
                                self.bs.on_bh()
                                stall_warned = False
                                if tag == "BH":
                                    acts = parse_bh(v)
                                    txt = fmt_damage(acts)
                                    self.q.put(("log", "battle", f"伤害结算：{txt}"))
                                    self.log("hit", f"  ⚔ {txt}")
                                elif tag == "BY":
                                    acts = parse_bh(v)  # BY 后面常继续拼 BH 段
                                    txt = fmt_damage(acts)
                                    self.q.put(("log", "battle",
                                                f"BY 战斗结算{('：' + txt) if txt else ''}"))
                                    self.log("hit", f"  ⚔ BY 战斗结算 "
                                                    f"{txt or v[:50]}")
                                else:
                                    self.q.put(("log", "battle", "BJ 战斗结算"))
                                    self.log("hit", f"  ⚔ BJ 战斗结算 {v[:40]}")
                            elif tag in ("BM", "BD"):
                                # 🔥 上毒结算包也必须解除 inflight（动作说明文档 §5）。
                                # 上毒这一轮服务器经常**只回** BM（刚中毒）/ BD（毒跳），
                                # 不回 BH。不认它们的话本轮永远 inflight，下一个
                                # BA low=0 会被当重复窗口丢掉 —— 上毒流程第二回合就卡死。
                                self.bs.on_bh()
                                stall_warned = False
                                if tag == "BM":
                                    # BM|槽位|flag|  flag=1 表示这次上毒命中
                                    seg = v[2:].split("|")
                                    try:
                                        bslot = int(seg[0], 16)
                                    except (ValueError, IndexError):
                                        bslot = -1
                                    bflag = seg[1] if len(seg) > 1 else "?"
                                    hit = (bflag == "1")
                                    self.q.put(("log", "battle",
                                                f"上毒{'成功' if hit else '未命中'}"
                                                f"：敌[0x{bslot:X}]"))
                                    self.log("hit", f"  ☠ 上毒结算 敌[0x{bslot:X}] "
                                                    f"{'命中' if hit else '未命中'}"
                                                    f"（flag={bflag}）")
                                else:
                                    self.q.put(("log", "battle", "毒跳结算"))
                                    self.log("hit", f"  ☠ 毒跳结算 BD {v[:40]}")
                            elif tag == "BE":
                                if in_battle:
                                    if self.cfg.get("mode") == "catch":
                                        resolve_catch_if_ready(False)
                                        resolve_catch_if_ready(True)
                                    dt = time.time() - battle_t0
                                    self.q.put(("log", "battle", f"战斗结束 · {dt:.1f}s · {rounds} 回合"))
                                    self.log("ok", f"  ✔ 战斗结束 BE（{dt:.1f}s，"
                                                   f"{rounds} 回合）")
                                    finish("BE")
                                    last_walk = time.time()
                                else:
                                    self.log("dim", f"  BE {'|'.join(f[1:])}")
                            else:
                                self.log("dim", f"  fid=15 {v[:60]}")

                            # ---- 复合 fid=15 的内嵌段 ----
                            # 不能只依赖首段 tag：组队包已经实测 BH...BE... 和
                            # BY...BT...BH...。主段处理完后补处理内嵌 BT/BE。
                            if embedded_bt:
                                stall_warned = False
                                bt = parse_bt(v)
                                if bt:
                                    if self.bs.on_bt(bt):
                                        self._bt_flag = bt["flag"]
                                    if self.cfg.get("mode") == "catch":
                                        self.q.put(("log", "battle",
                                                    f"捕捉结算：敌[0x{bt['target']:X}] "
                                                    f"flag={bt['flag']}"))
                                        self.log("hit", f"  🎯 内嵌 BT 捕捉结算 "
                                                        f"actor={bt['actor']:X} "
                                                        f"target={bt['target']:X} "
                                                        f"flag={bt['flag']}")
                                        resolve_catch_if_ready(False)

                            if embedded_be and in_battle:
                                if self.cfg.get("mode") == "catch":
                                    resolve_catch_if_ready(False)
                                    resolve_catch_if_ready(True)
                                dt = time.time() - battle_t0
                                self.q.put(("log", "battle",
                                            f"战斗结束 · {dt:.1f}s · {rounds} 回合"))
                                self.log("ok",
                                         f"  ✔ 战斗结束 BE（复合包，{dt:.1f}s，"
                                         f"{rounds} 回合）")
                                finish("BE(复合包)")
                                last_walk = time.time()
                            continue
                        if fid == "46":
                            if self.cfg["show46"]:
                                self.log("dim", f"  单位更新 {v[:70]}")
                            if v.startswith("K"):
                                kid = v.split("|", 1)[0].strip()
                                pet = parse_k_pet(v)
                                # 名字优先用 v2 的下标解析（第 20 段）；
                                # 老 parse_k_name 取“最后一个非数字字段”，在
                                # ...|乌力|厨子| 上会取成“厨子”，在
                                # ...|帖拉所伊朵|56.13.10.6 上取成数字串，都会漏判。
                                nm = (pet or {}).get("base_name") \
                                    or parse_k_name(v)
                                # ==========================================
                                # fid=46 处理四层（时序修正方案 §7）
                                # ==========================================
                                # 第二层：这条 K 是不是"刚才抓到的那只宠"。
                                # ⚠ 刻意不要求 catch_result_pending —— 那是战斗
                                # 统计的生命周期，一到 BE/最终BA 就关；而服务端
                                # 的完整长包可能更晚到。跟它绑定就会漏判。
                                pend_ok, pend_why = self.match_pend_slot(
                                    kid, pet, nm)
                                # 第三层：短包只记候选，长包才下结论
                                is_short = pet is not None and pet.get("partial")
                                if pend_ok and is_short:
                                    self._pend["cand"] = kid
                                    self.log("dim", f"  ⏳ 新候选槽 {kid}："
                                                    f"资料不完整（短包），"
                                                    f"等完整长包再判满档")
                                if pend_ok and not is_short:
                                    # 第一层：先完成宠物栏更新与合并
                                    # 第四层：new_catch -> _update_pet 内部判满档
                                    #         （必须先更新完再读结果，见下）
                                    self._update_pet(v, new_catch=True)
                                    pend = self._pend
                                    pend["cand"] = kid
                                    pend["full_done"] = True
                                    # ⚠ 关键：读**合并之后**的最终对象，
                                    # 而不是刚 parse 出来的临时 pet —— 真正的
                                    # 最终状态可能含短包留下的字段和算好的 full。
                                    final = self.pet_panel.get(kid) or {}
                                    if final.get("full"):
                                        self.log("ok", f"  ★ 已确认新抓宠 {kid} "
                                                       f"= {nm}（★满档，保留）")
                                    else:
                                        self.log("warn",
                                                 f"  已确认新抓宠 {kid} = {nm} "
                                                 f"（非满档）")
                                    # 丢弃决策：基于最终对象，且只做一次
                                    pend["drop_done"] = True
                                    drop = self.catch_cfg.get("drop_non_full")
                                    if final.get("full"):
                                        pass        # 满档：永不入队
                                    elif drop:
                                        self._enqueue_drop(kid, final)
                                    else:
                                        self.log("dim",
                                                 f"  {kid} 非满档，但未开启"
                                                 f"「丢弃不满档」，保留")
                                    pend["done"] = True
                                    self._decided_new_slots.add(kid)
                                    self.close_pend("已认回新宠并完成决策")
                                elif not pend_ok and self._pend is not None \
                                        and not self._pend.get("done") \
                                        and kid not in self._decided_new_slots:
                                    # 命中失败的诊断（不刷屏：只在有上下文时打）
                                    self.log("dim", f"  K 刷新 {kid}"
                                                    f"（{nm or '无名'}）："
                                                    f"{pend_why}"
                                                    f"，按普通刷新处理")
                                if not pend_ok or is_short:
                                    # 普通刷新 / 短包候选：照常更新宠物栏，
                                    # 但**不**做满档判定（文档：已有宠不判）
                                    self._update_pet(v, new_catch=False)
                                # 抓宠成功证据（文档 §13）：捕捉后会出现新的 K 槽，
                                # 尾部带宠物名。只做「同名」比对，不解析整个 K 协议。
                                if nm:
                                    self.k_names[kid] = nm
                                    if self.cfg.get("mode") == "catch" \
                                            and self.bs.catch_result_pending \
                                            and kid not in catch_k_before \
                                            and self.bs.on_k(kid, nm):
                                        self.log("ok", f"  ✔ 新 K 槽 {kid} = {nm}"
                                                       "（与捕捉目标同名）")
                                        # 兼容 BT -> K 与 K -> BT 两种包序。
                                        resolve_catch_if_ready(False)
                            continue
                        if fid == "41" and self.stop_phase != STOP_RUNNING:
                            # 停止流程专属：把地图里的 NPC / 场景物件列出来，
                            # 给用户一个"地图确实刷新了"的可验证证据。
                            # 运行期间不解析，避免动到稳定挂机循环（文档 §10）
                            objs = parse_map_objects(v)
                            if objs:
                                self.map_objects = objs
                                prev = "、".join(o["name"] for o in objs[:6])
                                self.q.put(("map_objects", (len(objs), prev)))
                                self.log("map", f"  🗺 地图/NPC 刷新：{len(objs)} 个"
                                                f"（{prev}"
                                                f"{'…' if len(objs) > 6 else ''}）")
                            continue
                        if fid == "42" and len(f) >= 3:
                            self.log("map", f"  ↩ 回到地图 ({f[1]},{f[2]})")
                            continue
                        if self.cfg["showraw"]:
                            self.log("dim", f"  fid={fid} {v[:60]}")

                # ---- 停止流程状态机（文档 §4.2 / §4.3 / §6 / §7）----
                # 只保护「停止」：运行期间 stop_phase 恒为 RUNNING，这里什么都不做。
                if self.stop_phase == STOP_PENDING and not in_battle:
                    # 战斗自然收尾了（BE / 敌方全灭 / 超时兜底都算）
                    self.map_sync_score = 0
                    self.map_sync_ready_at = 0.0
                    self.map_sync_t0 = time.time()
                    self.log("sys", "  ⌛ 战斗已结束，等待地图/NPC 刷新（fid="
                                    + "/".join(MAP_SYNC_FIDS) + "，需要 "
                                    + str(MAP_SYNC_SCORE_NEED) + " 个）")
                    self._set_stop_phase(MAP_SYNC_WAIT,
                                         f"0/{MAP_SYNC_SCORE_NEED}")
                elif self.stop_phase == MAP_SYNC_WAIT:
                    if self.map_sync_ready_at:
                        if time.time() >= self.map_sync_ready_at:
                            self.map_sync_ready_at = 0.0
                            self.log("ok", "  ✓ 地图/NPC 同步完成 —— 已稳定停止"
                                           "（战斗监听保持在线，可随时再开始）")
                            self._set_stop_phase(STOPPED_READY, "地图正常")
                    elif self.map_sync_score >= MAP_SYNC_SCORE_NEED:
                        # 分数够了也别立刻宣布完成：客户端还要刷 UI / 画 NPC
                        self.map_sync_ready_at = time.time() + MAP_READY_DELAY
                        self.log("dim", f"  地图同步达成（{self.map_sync_score}"
                                        f"/{MAP_SYNC_SCORE_NEED}），等待客户端刷新"
                                        f" {MAP_READY_DELAY}s")
                        self._set_stop_phase(
                            MAP_SYNC_WAIT,
                            f"{self.map_sync_score}/{MAP_SYNC_SCORE_NEED}")
                    elif time.time() - self.map_sync_t0 > MAP_SYNC_TIMEOUT:
                        self.log("warn", f"  ⚠ 等待地图同步超过 "
                                         f"{MAP_SYNC_TIMEOUT}s（只收到 "
                                         f"{self.map_sync_score} 个同步包），"
                                         "按已停止处理")
                        self._set_stop_phase(STOPPED_READY, "同步超时")

                # ---- 战斗兜底 ----
                # 正常流程已完全由 BA 驱动，这里只兜异常：
                #   · 一直收不到 BA low=0（报文丢了 / 中途勾选快速战斗）-> 主动发一轮
                #   · 回合数或总时长超上限 -> 收尾，别把角色锁在战斗里
                if in_battle:
                    el = time.time() - battle_t0
                    if self.cfg["fast_battle"]:
                        # 第一次实战刻意「不主动代发」：
                        # 我们正在验证 BA low==0 是不是唯一合法的行动窗口，
                        # 如果超时就自己发一发 W|1|F，就分不清是「服务器允许」
                        # 还是「我们瞎发但服务器刚好没断线」。所以只报警。
                        stall = (time.time() - last_act_t > 6.0) if rounds \
                            else (el > 5.0)
                        if stall and not stall_warned:
                            stall_warned = True
                            # 按状态给诊断，别再用"回执没凑齐"那套旧说法
                            if self.bs.round_inflight:
                                self.log("warn", "  ⚠ 本轮指令已提交超过 6s，"
                                                 "仍未收到战斗结算（BH/BJ/BT）"
                                                 "——保持静默，不主动代发")
                            else:
                                self.log("warn", "  ⚠ 超过 6s 未出现新的操作窗口"
                                                 "（没有 BA low=0）"
                                                 "——保持静默，不主动代发")
                        # attack/flee 保留回合硬上限；catch 到 30 回合时由
                        # catch_limit_pending 在下一合法 BA 窗口主动 E 逃跑。
                        # 无论什么模式，40s 总时长仍是最终异常兜底。
                        hard_round_limit = (
                            rounds >= MAX_BATTLE_ROUNDS
                            and self.cfg.get("mode") != "catch"
                        )
                        if hard_round_limit or el > BATTLE_TIMEOUT:
                            if self.cfg.get("mode") == "catch":
                                resolve_catch_if_ready(False)
                                resolve_catch_if_ready(True)
                            finish(f"超过 {MAX_BATTLE_ROUNDS} 回合 / "
                                   f"{BATTLE_TIMEOUT}s，兜底")
                            last_walk = time.time()
                    elif el > 120.0:          # 旁观模式下只是没收到 BE
                        in_battle = False
                    time.sleep(0.15)
                    continue

                # ---- 战后自动恢复（文档 §20/§47/§69）----
                # 位置极其关键：
                #   · 必须在 packet dump **之后**（否则 WAIT_QI/WAIT_HEAL 期间
                #     Engine 停止消费服务端报文，文档 §49）
                #   · 必须在「确认不在战斗」之后
                #   · 必须在 fid=43 熔断 / 遇敌走位 **之前**
                #     （先遇敌的话治疗还没发就又开打了，功能形同无效，§21）
                if self._recovery_pending:
                    was_pending = self._recovery_pending
                    try:
                        snap_r = self.g.snapshot()
                        busy = self._post_battle_recovery_tick(snap_r)
                    except Exception as e:
                        # 恢复是附加能力：它自己炸了也绝不能把 Engine 打成 fatal
                        # （文档 §52 / §53）
                        busy = False
                        self._fail_recovery(f"恢复流程异常："
                                            f"{type(e).__name__}: {e}")
                        snap_r = None

                    # 背包 2..15 全局走完仍无气力回复 -> 整个 Engine 主循环退出
                    if self._global_break:
                        self.log("warn", f"■ Engine 主循环退出："
                                         f"{self._global_break_reason}")
                        break

                    # 恢复刚结束：重算遇敌间隔，别在同一毫秒立刻发 fid=1（§68）
                    if was_pending and not self._recovery_pending:
                        last_walk = time.time()

                    if busy:
                        # 本轮不走 hazard / 不遇敌 / 不发其它地图动作
                        self.stat(battles=battles, walks=walks, sent14=sent14,
                                  h43=fid_in.get("43", 0), state=snap_r)
                        time.sleep(0.05)
                        continue

                # ---- fid=43 熔断 ----
                if hazard:
                    if time.time() > paused_until:
                        if not auto:
                            # 只监听：熔断照样解除，但不代发走位包
                            hazard = 0
                            last_walk = time.time()
                            self.log("dim", "  熔断结束（只监听，不代发走位包）")
                            continue
                        s = self.g.snapshot()
                        dx = 1 if s["x"] < HOME[0] else (-1 if s["x"] > HOME[0] else 0)
                        dy = 1 if s["y"] < HOME[1] else (-1 if s["y"] > HOME[1] else 0)
                        step = next((k for k, v in md.DIRS.items() if v == (dx, dy)), "c")
                        self.b.send(enc(fe.build_walk(s["x"], s["y"], step, self.key)))
                        self.log("warn", f"  熔断结束，({s['x']},{s['y']}) → 回 {HOME} 走 {step}")
                        hazard = 0
                        last_walk = time.time()
                    time.sleep(0.2)
                    continue

                # ---- 遇敌走位 ----
                # ⚠ 走位也是「自动行为」：没点「开始自动战斗」就一个包都不发，
                # 只监听（文档：监听永远在线，执行由用户控制）
                # 恢复状态机没结束就绝不发新的 fid=1 遇敌走位（文档 §22）
                if auto and self.cfg["fast_enc"] and not self._recovery_pending:
                    s = self.g.snapshot()
                    # 抖动要远小于间隔：原来 uniform(0,.4) 会把 100ms 拖到最多
                    # 500ms；改成 ±20ms，让实际间隔贴近设定值
                    jitter = random.uniform(-0.02, 0.02)
                    wait = max(0.05, self.cfg["interval"] + jitter)
                    if s["state"] == 9 and time.time() - last_walk >= wait:
                        if s["map"] != MID:
                            MID = s["map"]
                            MI = md.load(MID)
                            HOME = (s["x"], s["y"])
                            AXIS = md.pick_axis(MI, *HOME) if MI else ("c", "g")
                            self.log("warn", f"  地图变为 {MID}，HOME 重置 {HOME} 轴 {AXIS}")
                        # AXIS 可能在当前落点暂时找不到。不要因此停掉遇敌线程；
                        # 每个走位窗口都重新试一次，找到后自动恢复地形保护。
                        if MI and not AXIS:
                            AXIS = md.pick_axis(MI, s["x"], s["y"])
                            if AXIS:
                                self.log("sys", f"已恢复安全摆动轴 {AXIS}")
                        if MI and AXIS:
                            dx, dy = md.DIRS[AXIS[0]]
                            if not (MI.safe(s["x"] + dx, s["y"] + dy) and
                                    MI.safe(s["x"] - dx, s["y"] - dy)):
                                AXIS = md.pick_axis(MI, s["x"], s["y"]) or AXIS
                            d1, d2 = AXIS
                            best, d0 = None, (s["x"] - HOME[0]) ** 2 + (s["y"] - HOME[1]) ** 2
                            for d in (d1, d2):
                                ddx, ddy = md.DIRS[d]
                                if (s["x"] + ddx - HOME[0]) ** 2 + \
                                   (s["y"] + ddy - HOME[1]) ** 2 < d0:
                                    best = d
                                    break
                            first = best if best else (d1 if walks % 2 == 0 else d2)
                            path = (first + (d2 if first == d1 else d1)) * 10
                        else:
                            path = ("gc" if walks % 2 == 0 else "cg") * 10
                        self.b.send(enc(fe.build_walk(s["x"], s["y"], path, self.key)))
                        walks += 1
                        last_walk = time.time()
                        if walks % 20 == 0:
                            self.log("dim", f"  …已发 {walks} 个遇敌包")
                snap = self.g.snapshot()
                # 文档 §2.1 生命周期：离开 state9 就摘掉监听标记，回来再挂上。
                # 战斗中 state=10 不算离开（已排除），否则一进战斗监听就"离线"。
                if snap.get("state") in OUT_OF_WORLD_STATES \
                        and self.battle_hook_active:
                    self.battle_hook_active = False
                    self.q.put(("hook_state", False))
                    self.log("dim", "已离开 state9，战斗监听标记关闭")
                elif snap.get("state") == 9 and not self.battle_hook_active:
                    self.battle_hook_active = True
                    self.q.put(("hook_state", True))
                    self.log("dim", "回到 state9，战斗监听重新在线")
                self.stat(battles=battles, walks=walks, sent14=sent14,
                          h43=fid_in.get("43", 0), state=snap)
                # 主循环粒度必须远小于走位间隔：旧值 0.2s 会把 interval=0.1
                # (100ms) 吃掉，实际只能到 200ms 以上
                time.sleep(0.02)
        except Exception as e:
            import traceback
            self.q.put(("fatal", f"{type(e).__name__}: {e}\n{traceback.format_exc()}"))
        finally:
            try:
                finish("退出前收尾")
            except Exception:
                pass
            fh.close()
            self.teardown()
            self.battle_hook_active = False
            self.q.put(("hook_state", False))
            self.q.put(("done", {"battles": battles, "walks": walks,
                                 "sent14": sent14, "fid_in": fid_in}))
