"""战斗状态机（重构 v2.2 §5~§9）：BA/BC/BH 状态维护 + 猛毒/抓宠决策。

⚠ 本模块只回答「我要做什么」，不负责「怎么发送」（v2.2 §9）：
    决策结果 = Command（一次操作机会的两条 fid=14 指令），
    真正发包由 Engine 做（当前 key / fid 编码 / send / 日志 / 熔断）。
    这里不许出现 frida / socket / key / Tk。

第一批迁移（v2.2 §7）：
    战斗变量  round_inflight / pending_window / victory_pending / last_units
              （文档里的 last_battle_state 在本代码里是
                battle_had_enemy + victory_pending 两个开关）
    抓宠变量  psm / pslot / pname / php_before / pverified / pexcluded
    毒状态    SEARCH/POISON_TEST/WAIT_POISON/VERIFY_FULL/POISON_CONTROL/CATCH
第二批（v2.2 §8 暂缓）：K包认回 —— 仍留在 Engine（时序复杂）。

允许依赖：stw_config / stw_protocol / stw_pet。
禁止依赖：stw_ui / frida / auto_encounter / fast_encounter / sa_codec。
"""
from stw_config import (BA_ACT, MAX_BATTLE_ROUNDS, POISON_DMG_MODES,
                        POISON_VERIFY_MODES)
from stw_pet import pick_catch_target, unit_by_slot, verify_poison_full
from stw_protocol import (alive_enemy_slots, build_round, pick_enemy_target)


class Command:
    """Battle 的一次决策结果（v2.2 §9 的 Command(type="fid14", lines=[...])）。

    kind:
        "fid14"   —— 代发一轮战斗指令。lines 恒为两条（角色 + 战宠）：
                     只发一条服务器会一直等另一个单位，本回合永不结算。
        "victory" —— 敌方全灭 + 最终 BA low=0：不发 fid14，由 Engine 补
                     fid=8 收尾（服务器胜利时不发 BE）。
        "none"    —— 这个窗口什么都不发（本轮已提交未结算 / 没有合法目标 /
                     策略要求静默）。

    Engine 侧副作用靠这几个标记携带（Battle 不碰 catch_stats / _pend）：
        attempt          本次是发起捕捉 -> Engine 开新宠上下文 + attempts+1
        no_match         本次没匹配到抓宠规则 -> Engine 的 no_match+1
        hpmax_matched    本次**首次锁定**一个通过第一层规则的候选
        poison_confirmed 本次刚完成 verify_poison_full(ok=True)

    ⚠ 两个统计标记都是**一次性**的：只在 Battle 自己已经存在的真实判定点
    挂上，Engine 只负责累加。不另造 stat_events / _stat_seen —— 状态机天然
    保证同一目标只会在 begin() 里锁一次、只会在 ok=True 时确认一次。
    """

    __slots__ = ("kind", "lines", "mode", "target", "why", "name",
                 "attempt", "no_match", "set_psm",
                 "hpmax_matched", "poison_confirmed")

    def __init__(self, kind, lines=None, mode=None, target=None, why="",
                 name=None, attempt=False, no_match=False, set_psm=None,
                 hpmax_matched=False, poison_confirmed=False):
        self.kind = kind
        self.lines = lines or []
        self.mode = mode
        self.target = target
        self.why = why
        self.name = name
        self.attempt = attempt
        self.no_match = no_match
        self.set_psm = set_psm
        self.hpmax_matched = hpmax_matched
        self.poison_confirmed = poison_confirmed

    def __repr__(self):
        return (f"Command({self.kind}, mode={self.mode}, "
                f"target={self.target}, lines={self.lines})")


class BattleSession:
    """一场战斗的状态机（v2.2 §6）。"""

    def __init__(self, cfg, catch_cfg, log=None, resolve_catch=None):
        self.cfg = cfg
        self.catch_cfg = catch_cfg
        self.log = log if log is not None else (lambda kind, text: None)
        # 抓宠结算回调：战斗统计闭环在 Engine（要动 catch_stats / _pend）
        self.resolve_catch = resolve_catch or (lambda force: None)
        self.reset_battle()

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def reset_battle(self):
        """fid=7（遇敌）：整场状态重置。

        ⚠ pexcluded 是「本场排除」：上一场验证失败的槽不能带进新的一场。
        """
        self.last_units = []
        self.round_inflight = False
        self.victory_pending = False
        self.battle_had_enemy = False
        self.pending_window = False
        self.pending_window_rnd = 0
        self.catch_limit_pending = False
        # —— 抓宠跟踪（文档 §11.1）——
        self.last_catch_target = None
        self.last_catch_name = None
        self.catch_bt_seen = False
        self.catch_k_seen = False
        self.catch_k_name = None
        self.catch_result_pending = False
        self.catch_result_resolved = False
        # —— 上毒（猛毒）状态机（抓宠智能筛选 v2 §10）——
        # SEARCH -> POISON_TEST -> WAIT_POISON -> VERIFY_FULL
        #        -> POISON_CONTROL -> CATCH
        self.psm = "SEARCH"
        self.pslot = None
        self.pname = None
        self.php_before = None
        self.pverified = False      # = 文档里的 poison_verified：验证/控血分界
        self.pv_tries = 0
        self.pexcluded = set()

    def finish_battle(self):
        """战斗收尾（BE / 敌方全灭 / 超时兜底）：清掉本场协议状态。"""
        self.round_inflight = False
        self.victory_pending = False
        self.battle_had_enemy = False
        self.catch_limit_pending = False
        self.pending_window = False

    # ------------------------------------------------------------------
    # 报文 -> 状态
    # ------------------------------------------------------------------
    def on_bc(self, units, in_battle=False):
        """BC（队伍数据）：更新单位 + 胜利判定。

        返回 (存活敌方槽列表, 本次是否刚确认全灭)。
        ⚠ 胜利必须「本场确实见过敌人」才算：否则 BC 解析异常 / 初始化 BC
        不完整会误判成胜利（服务器胜利时不发 BE，只把敌方 hp 抹成 0）。
        """
        self.last_units = units
        alive = alive_enemy_slots(units)
        victory = False
        if alive:
            self.battle_had_enemy = True
            self.victory_pending = False
        elif in_battle and self.battle_had_enemy:
            self.victory_pending = True
            victory = True
        return alive, victory

    def on_ba(self, low, rnd):
        """BA：记住 low==BA_ACT 的操作窗口。

        只监听（还没点「开始自动战斗」）时也要记：用户点开始时服务器通常
        已经在等指令，不会再补发第二个 BA（文档 §9）。
        """
        if low == BA_ACT:
            self.pending_window = True
            self.pending_window_rnd = rnd

    def on_bh(self):
        """结算包到达（BH/BJ/BY/BT/BM/BD）：本轮指令已提交并结算。

        🔥 上毒这一轮服务器经常**只回** BM（刚中毒）/ BD（毒跳），不回 BH；
        不认它们的话本轮永远 inflight，下一个 BA low=0 会被当重复窗口丢掉。
        """
        self.round_inflight = False

    def on_bt(self, bt):
        """BT 捕捉结算。返回是否命中本次捕捉目标（Engine 据此记 _bt_flag）。"""
        self.round_inflight = False
        if bt and bt["target"] == self.last_catch_target:
            self.catch_bt_seen = True
            return True
        return False

    def on_k(self, kid, name):
        """fid=46：出现与本次捕捉目标同名的新 K 槽（捕捉成功的 K 侧证据）。

        返回 True 表示记到了新证据（调用方随后可尝试闭环）。
        ⚠ 「是不是新槽」由 Engine 判（k_names / catch_k_before 属 K包认回，
        v2.2 §8 留第二阶段），这里只认名字。
        """
        if self.catch_result_pending and name == self.last_catch_name:
            self.catch_k_seen = True
            self.catch_k_name = f"{name} → {kid}"
            return True
        return False

    def mark_sent(self, cmd=None):
        """Engine 已把这一轮 fid=14 发出去 —— 推进协议状态与抓宠跟踪。"""
        self.round_inflight = True
        if cmd is None:
            return
        if cmd.set_psm:
            self.psm = cmd.set_psm
        if cmd.attempt:
            self.last_catch_target = cmd.target
            self.last_catch_name = cmd.name
            self.catch_bt_seen = False
            self.catch_k_seen = False
            self.catch_k_name = None
            self.catch_result_pending = True
            self.catch_result_resolved = False

    # ------------------------------------------------------------------
    # 决策：一个 BA low=0 操作窗口
    # ------------------------------------------------------------------
    def decide_action(self, rnd=0, rounds=0, catch_stop=False):
        """处理一个 BA low=0 操作窗口，返回 Command。

        ⚠ 铁律：**返回 fid14 时调用方一定已经发过指令**。操作窗口是服务器
        给的一次性机会，不发东西服务器就一直等，这一回合直接卡死。
        「排除目标」这种看似什么都不用做的分支，必须当场换目标再发一轮。
        """
        self.pending_window = False
        mode = self.cfg["mode"]

        # 胜利路径放在最前：它属于「状态维护」不是代打指令，只监听时也要认账，
        # 否则战斗会一直挂着等 40s 兜底。
        if self.victory_pending:
            if mode == "catch":
                # 最后一只可能是"被抓走"而不是打死，先把捕捉证据结算掉
                self.resolve_catch(False)
                self.resolve_catch(True)
            self.round_inflight = False
            self.victory_pending = False
            return Command("victory", why="敌方全灭")
        # ⚠ 只按协议状态判断，不看时间：实测第二回合的 BA|18000|1| 距上一轮
        # 发包只有 0.153s，用时间阈值去重会吞掉合法窗口 -> 战斗卡死。
        if self.round_inflight:
            self.log("dim", "  BA low=0，但本轮指令已提交、"
                            "还没结算，忽略重复窗口")
            return Command("none", mode=mode)

        if mode == "catch":
            # 新操作窗口意味着上一轮已经彻底过去：先给乱序到达的 K/BC 最后
            # 一次机会闭环成功；仍无完整证据才记"待确认"，且只记一次。
            self.resolve_catch(False)
            self.resolve_catch(True)
            # 「抓到即停 / 达数量停止」不能直接掐线程，否则角色锁在战斗里
            if catch_stop:
                return self._cmd("flee", None,
                                 "已达抓宠停止条件，安全结束本场")
            # 连续抓宠达上限：必须等合法操作窗口再主动逃跑，不能 fid=8 硬切
            if self.catch_limit_pending:
                self.log("warn",
                         f"  ⚠ 抓宠已达 {MAX_BATTLE_ROUNDS} 回合，"
                         "本回合主动逃跑")
                self.catch_limit_pending = False
                return self._cmd("flee", None,
                                 f"抓宠达到 {MAX_BATTLE_ROUNDS} 回合上限")
            if self.catch_cfg.get("poison_enabled"):
                cmd = self._catch_with_poison()
                if cmd is not None:
                    return self._limit(cmd, rounds)
                # None = 没目标可毒可抓，落回下面的兜底

        if mode == "flee":
            tgt = None                      # 逃跑不依赖敌方目标
        elif mode == "catch":
            unit = pick_catch_target(
                self.last_units, self.catch_cfg.get("rules") or {},
                exclude=self.pexcluded)
            if unit is None:
                return self._no_match()
            tgt = unit["slot"]
            cmd = self._cmd(mode, tgt, f"BA low=0 回合{rnd}",
                            pet_action=self.catch_cfg.get("pet_action",
                                                          "attack"))
            cmd.attempt = True
            cmd.name = unit.get("name")
            # 关掉「抓宠前上毒」时也要统计第一层命中（毒伤确认恒为 0）
            cmd.hpmax_matched = True
            return self._limit(cmd, rounds)
        else:
            tgt = pick_enemy_target(self.last_units)
            if tgt is None:
                self.log("warn", "  ✗ BA low=0，但当前 BC 中没有"
                                 "存活敌方，不发送")
                return Command("none", mode=mode)
        return self._cmd(mode, tgt, f"BA low=0 回合{rnd}",
                         pet_action=self.catch_cfg.get("pet_action", "attack"))

    # ------------------------------------------------------------------
    # 内部：指令构造 / 兜底 / 上限
    # ------------------------------------------------------------------
    def _cmd(self, mode, target, why, pet_action="attack", skill=None):
        """构造一轮 fid=14 指令（不发送）。"""
        if mode != "flee" and target is None:
            self.log("warn", f"  ✗ 拒绝代发：没有合法目标（{why}）")
            return Command("none", mode=mode, target=target, why=why)
        return Command("fid14", build_round(mode, target, skill, pet_action),
                       mode=mode, target=target, why=why)

    def _limit(self, cmd, rounds):
        """抓宠达 MAX_BATTLE_ROUNDS：不硬切，等下一次合法窗口主动逃跑。"""
        if cmd.kind == "fid14" and rounds + 1 >= MAX_BATTLE_ROUNDS:
            self.catch_limit_pending = True
            self.log("warn", f"  ⚠ 已尝试抓宠 {rounds + 1} 回合；"
                             "等待下一次 BA low=0 后主动逃跑")
        return cmd

    def _no_match(self):
        """没有符合抓宠规则的目标：按配置的兜底动作。"""
        fallback = self.catch_cfg.get("no_match_action", "flee")
        if fallback == "flee":
            cmd = self._cmd("flee", None, "无符合抓宠规则的目标")
        elif fallback == "attack":
            tgt = pick_enemy_target(self.last_units)
            if tgt is None:
                self.log("warn", "  ✗ 无抓宠目标，且没有可攻击的存活敌方")
                cmd = Command("none", mode="catch")
            else:
                cmd = self._cmd("attack", tgt, "无抓宠目标，按设置攻击")
        else:
            self.log("dim", "  无抓宠目标，保持静默")
            cmd = Command("none", mode="catch")
        cmd.no_match = True
        return cmd

    def _poison_cmd(self, slot, why, next_state):
        """一轮上毒：J|{技能格}|{目标} + 战宠待机 W|FF|FF。

        next_state 决定发完之后停在哪个阶段（v2.2 §6：两阶段不能共用同一套
        Δhp 判断）：
          "WAIT_POISON"    验证阶段（还没确认满档）→ 下一轮看 Δhp
          "POISON_CONTROL" 控血阶段（已验证）      → 下一轮只看血量比例
        ⚠ 控血阶段**不能**回到 WAIT_POISON：猛毒最低保留 HP=1，一旦毒到
        HP=1 就永远 Δhp=0，再按「Δhp=0 → 补毒」处理就是无限循环（v2.2 §1）。
        """
        skill = self.catch_cfg.get("poison_skill", 2)
        try:
            skill = int(skill)
        except (TypeError, ValueError):
            skill = 2
        return Command("fid14", build_round("poison", slot, skill),
                       mode="poison", target=slot, why=why,
                       set_psm=next_state)

    def _catch_cmd(self, tgt, why):
        """一轮抓宠：T|{目标} + 战宠待机（上毒流程一律 W|FF|FF，文档 §9）。"""
        return Command("fid14", build_round("catch", tgt, None, "wait"),
                       mode="catch", target=tgt, why=why, name=self.pname,
                       attempt=True, set_psm="CATCH")

    # ------------------------------------------------------------------
    # 猛毒 / 抓宠状态机（抓宠智能筛选 v2 §3~§9 + v2.2 修正）
    # ------------------------------------------------------------------
    def _catch_with_poison(self):
        """SEARCH→POISON_TEST→WAIT_POISON→VERIFY_FULL→POISON_CONTROL→CATCH。

        文档 §10 列了 9 个状态，这里合并：CHECK_LEVEL + CHECK_MAX_HP ==
        pick_catch_target() 的第一层初筛；VERIFY_FULL == 未验证分支里 Δhp>0
        之后的那段判定；DONE == send_catch 之后的 CATCH（结果交给既有
        BT/K/BC 证据闭环，不另设终态）。

        ===== v2.2：两个阶段必须分开（HP=1 是猛毒的正常边界）=====
        猛毒最低保留 HP=1，目标被毒到 1 之后 Δhp 恒为 0。如果控血阶段还在
        判 Δhp，就会「补毒→HP不变→补毒」无限循环。所以**第一层判断是
        pverified**：
          未验证（POISON_TEST/WAIT_POISON/VERIFY_FULL）：只看 Δhp
              Δhp=0  -> 补毒，绝不抓
              Δhp>0  -> 满档四维验证：失败(strict)排除 / 通过 -> 进控血
          已验证（POISON_CONTROL）：**只看 hp/hpmax，不再看 Δhp**
              hp/hpmax < 阈值 -> 抓宠
              否则            -> 续毒（且停在 POISON_CONTROL）
        Δhp 只负责满档验证，HP比例只负责最终抓捕，两者不混用。

        返回 Command（调用方必须发）；
        None = 没有可毒可抓的目标，交给调用方走「未命中」兜底。
        """
        rules = self.catch_cfg.get("rules") or {}
        try:
            ratio = float(self.catch_cfg.get("poison_hp_ratio", 0.10))
        except (TypeError, ValueError):
            ratio = 0.10
        skill = self.catch_cfg.get("poison_skill", 2)
        vmode = self.catch_cfg.get("poison_verify", "log")
        dmode = self.catch_cfg.get("poison_dmg_mode", "derived")
        if vmode not in POISON_VERIFY_MODES:
            vmode = "log"
        if dmode not in POISON_DMG_MODES:
            dmode = "derived"

        # 本次 decide_action 里**是否刚刚发生了一次新的毒伤确认**。
        # 这是局部一次性标记，不是 BattleSession 长期状态：
        #   · 只在 verify_poison_full() 返回 ok=True 时置 True；
        #   · off 模式 / log 模式验证失败虽然也会 pverified=True，**绝不算确认**。
        poison_confirmed = False

        def drop_target(why):
            """放弃当前目标并清空验证状态（排除 / 离场都走这里）。"""
            self.pexcluded.add(self.pslot)
            self.log("dim", f"  目标 0x{self.pslot:X} 已放弃（{why}）")
            self.psm, self.pslot, self.pname = "SEARCH", None, None
            self.php_before, self.pverified = None, False
            self.pv_tries = 0

        # 目标还在吗？（被抓走 / 被打死 / 换场都要重新找）
        was = self.psm
        if self.pslot is not None:
            cur = unit_by_slot(self.last_units, self.pslot)
            if cur is None or cur.get("hp", 0) <= 0:
                self.log("dim", f"  目标 0x{self.pslot:X} 已离场"
                                f"（{was}）→ 重新初筛")
                self.psm, self.pslot, self.pname = "SEARCH", None, None
                self.php_before, self.pverified = None, False
                self.pv_tries = 0
                # CATCH 之后目标没了（抓走 / 被毒死）：不 return，
                # 让下面的 SEARCH 分支重新初筛并对新目标走完整上毒流程。

        def begin(unit):
            """锁定一个新目标并立刻上毒（SEARCH 的唯一出口）。"""
            self.pslot = unit["slot"]
            self.pname = unit.get("name")
            self.php_before = unit.get("hp")
            self.pverified = False      # 阶段开关（= poison_verified）
            self.pv_tries = 0
            self.psm = "POISON_TEST"
            self.log("ok", f"  🎯 初筛命中 {self.pname} "
                           f"Lv{unit.get('lv')} "
                           f"{unit.get('hp')}/{unit.get('hpmax')}"
                           f"（槽 0x{self.pslot:X}）→ 上毒验证")
            cmd = self._poison_cmd(self.pslot, f"猛毒验证 技能格{skill}",
                                   "WAIT_POISON")
            # ★ 第一层命中只在「首次锁定」记一次：之后补毒走 _poison_cmd()，
            #   控血走下面的分支，都不会再经过 begin()，天然不重复。
            cmd.hpmax_matched = True
            return cmd

        def search():
            """按规则库初筛（等级 + HP上限），命中就上毒。"""
            unit = pick_catch_target(self.last_units, rules,
                                     exclude=self.pexcluded)
            return begin(unit) if unit is not None else None

        if self.psm == "SEARCH":
            return search()

        cur = unit_by_slot(self.last_units, self.pslot)
        if cur is None or cur.get("hp", 0) <= 0:
            # 最后一道防线：同样走 search() 而不是返回 None ——
            # 交给调用方会退化成「不上毒直接抓」，把验证流程整个跳过。
            self.psm, self.pslot = "SEARCH", None
            return search()

        # ===========================================================
        # v2.2 §6 第一层：是否已经验证 —— 两阶段从此分流
        # ===========================================================
        if not self.pverified:
            # ---- 验证阶段：只看 Δhp，不看血量比例；HP=1 也绝不抓 ----
            st = cur.get("state")
            delta = (self.php_before - cur["hp"]) \
                if self.php_before is not None else 0
            self.php_before = cur["hp"]
            if delta <= 0:
                # 猛毒成功率只有 25~30%，没中毒不算失败，补一发
                self.pv_tries += 1
                # ⚠ HP=1 是猛毒机制的下限：掉血不会再发生，Δhp 永远 0。
                #   连续两次确认到这个边界就说明这只**不可能**做满档验证。
                if cur.get("hp", 0) <= 1 and self.pv_tries >= 2:
                    self.log("warn",
                             "  ✗ 目标 HP=1（猛毒最低保留 1），"
                             "永远拿不到 Δhp，无法做满档验证 → 排除")
                    drop_target("HP=1，无法验证")
                    return search()
                self.log("dim", f"  ☠ 毒未生效（Δhp=0"
                                f"{'' if st is None else f'，state={st}'}，"
                                f"{cur['hp']}/{cur['hpmax']}）→ 再上毒")
                return self._poison_cmd(self.pslot, "猛毒重试", "WAIT_POISON")
            self.log("ok", f"  ☠ 毒跳生效 Δhp={delta}"
                           f"（{cur['hp']}/{cur['hpmax']}）→ 四维验证")
            if vmode == "off":
                self.pverified = True
                self.log("dim", f"  四维验证已关闭（{vmode}）→ 直接控血")
            else:
                ok, expect = verify_poison_full(cur.get("lv"),
                                                cur.get("hpmax"),
                                                delta, dmode)
                if ok:
                    self.pverified = True
                    poison_confirmed = True
                    self.log("ok", f"  ✔ 四维验证通过（Δhp={delta} ∈ 预期"
                                   f"{sorted(expect)}）")
                else:
                    msg = (f"  ✗ 四维验证不通过：Δhp={delta}，"
                           f"Lv{cur.get('lv')}/{cur.get('hpmax')} 的满档预期"
                           f"={sorted(expect) if expect else '无（该等级+HP上限不可能是满档）'}")
                    if vmode == "strict":
                        self.log("warn", msg + " → 排除该目标")
                        drop_target("四维验证失败(strict)")
                        # 当场换下一只：不能「已处理」却什么都不发
                        return search()
                    # log 模式：毒伤公式口径还没实测确认，不敢据此排除，
                    # 只提示。但**仍然要进控血**，否则永远抓不到宠。
                    self.log("warn", msg + f" → 当前为「{vmode}」模式，"
                                           "仅记录不排除，仍进控血")
                    self.pverified = True
            self.psm = "POISON_CONTROL"
            self.log("ok", "  ✔ 进入控血阶段（poison_verified=True，"
                           "之后只看血量比例，不再看 Δhp）")

        # ===========================================================
        # 控血阶段：只看 hp / hpmax（v2.2 §5）
        # ===========================================================
        hpmax = cur.get("hpmax") or 0
        hp = cur.get("hp") or 0
        if hpmax > 0 and hp / hpmax < ratio:
            self.log("ok", f"  ✔ 血量 {hp}/{hpmax} = "
                           f"{hp / hpmax:.1%} < {ratio:.0%} → 抓宠")
            cmd = self._catch_cmd(self.pslot, "控血达标，捕捉")
            cmd.poison_confirmed = poison_confirmed
            return cmd
        pct = f"{hp / hpmax:.1%}" if hpmax else "?"
        # HP=1 是猛毒的正常边界，不是异常；这里**不能**因为 Δhp=0 就再判一遍
        note = "（HP=1，猛毒下限，Δhp=0 属正常）" if hp <= 1 else ""
        self.log("dim", f"  ☠ 继续控血 {hp}/{hpmax}（{pct}）{note} → 再上毒")
        cmd = self._poison_cmd(self.pslot, f"控血中 {pct}", "POISON_CONTROL")
        # 验证通过那轮如果血还厚，会走这里 —— 标记必须跟着走，不能丢
        cmd.poison_confirmed = poison_confirmed
        return cmd
