"""STW 风格交互界面：控制台先开，自己拉起游戏，检测到登入了才解锁按钮。

运行（必须用带 tkinter 的解释器，managed python 没有 tkinter）：
    C:\\Users\\ptelegion\\sqsd_py\\.venv\\Scripts\\python.exe stw_ui.py

完整流程（推荐 A 路：自己开游戏，控制台只做旁观/代打）：
  A. 你自己双击快捷方式开 sa_2903.exe（父进程是 explorer，不属于任何 Job）
     → 控制台「刷新客户端列表」→ 选中你的那个 → 「附加」
  B. 或者让控制台自己拉起（会优先走 explorer 的 ShellExecute 脱离 Job，
     实在不行才退回普通子进程——那时控制台没了游戏会跟着没）
  之后共同流程：
  3. 后台扫描游戏主模块内存，找形如 `<账号>bing\\0` 的 L2 密钥串
     （实测 <账号>bing 在主模块映像段 0x2f3be48）
  4. 等到 state==9（已进地图）→ 控制台按钮解锁，显示识别到的账号

进程安全：STW0.30.exe 拉起来的那个客户端永远被排除，控制台不会碰它。
控制台自身：任何回调/线程异常都只记录不退出，关窗口也不杀游戏。

界面分工：
  [x] 快速遇敌  —— 周期性代发 fid=1 走位包触发遇敌
  [x] 快速战斗  —— 勾选后才装 0x449353 钩子把 set_state(10) 改成 9，
                    跳过整个战斗界面；同时代发 fid=14 指令并补发 fid=8。
                    不勾选则游戏正常进战斗界面，本界面只做文字旁观，
                    绝不注入任何战斗包（fid=14 / fid=8 都不发）。
  文字战斗面板  —— 无论跳不跳界面，都按回合显示双方单位与状态。
"""
import faulthandler
import os
import queue
import subprocess
import sys
import threading
import time
import traceback
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

import psutil

# ---------------------------------------------------------------------------
# 重构 v2.0：路径/常量 -> stw_config，宠物逻辑 -> stw_pet，协议解析 -> stw_protocol，
# 后台引擎 -> stw_engine。本文件只留 UI；⚠ stw_config 必须最先导入——它负责把
# BASE_DIR / shit/ 注册进 sys.path，后面的 auto_encounter 等目录依赖才找得到。
#
# Engine 专属的常量（BA_* / MAP_SYNC_* / MAX_BATTLE_ROUNDS / RN_MAX / WRITE_SITE
# / LOG / ALLY_SLOT_MAX / ENEMY_SLOT_MIN …）已随 Engine 一起搬到 stw_engine.py，
# 这里只留 UI 自己要显示的那些（STATE_TXT / SLOT_ROWS / 停止流程文案 / 毒伤口径
# 单选文案 / 游戏路径 / 日志路径）。
# ---------------------------------------------------------------------------
from stw_config import (CONSOLE_LOG, CRASH_LOG, GAME_ARGS,
                        GAME_CWD, GAME_EXE, MAP_SYNC_WAIT,
                        POISON_DMG_MODES, POISON_VERIFY_MODES,
                        SLOT_ROWS, STATE_TXT, STOPPED_READY, STOP_PENDING,
                        STOP_RUNNING)
import auto_encounter as ae  # noqa: E402（UI 的「检查加速补丁状态」要用 ae._is_stw_child）
import frida  # noqa: E402（旧的 Tracer 诊断类仍在用，见 §8.1，本任务不动它）
from stw_process import (apply_speed_patch, fmt_client, hb, hb_thread,
                         install_exit_probe, launch_game_detached,
                         list_clients, speed_state)
from stw_watch import Watcher
from stw_protocol import units_to_slots
from stw_pet import (CATCH_SAMPLE_TEXT, PET_SLOTS, load_catch_rules,
                     parse_catch_rule_text, save_catch_rules)
from stw_engine import Engine  # noqa: E402

# 退出诊断：游戏"闪退"时在事件日志里不留痕（说明是主动退出而非未处理异常），
# 只能靠钩子抓是谁调的 ExitProcess / TerminateProcess，以及调用栈。
TRACE_JS = r"""
function bt(ctx) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE).map(function (a) {
      try { return DebugSymbol.fromAddress(a).toString(); }
      catch (e) { return a.toString(); }
    });
  } catch (e) { return ['backtrace 失败: ' + e]; }
}
function hook(mod, name) {
  var p = null;
  try { p = mod.getExportByName(name); } catch (e) { return; }
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(a) {
      send({evt: name, arg0: a[0] ? a[0].toString() : '0', bt: bt(this.context)});
    }
  });
}
try {
  var k = Process.getModuleByName('kernel32.dll');
  ['ExitProcess', 'TerminateProcess', 'FatalExit', 'RaiseException']
    .forEach(function (n) { hook(k, n); });
  var n = Process.getModuleByName('ntdll.dll');
  ['RtlExitUserProcess', 'NtTerminateProcess'].forEach(function (x) { hook(n, x); });
  send({evt: 'tracer-ready'});
} catch (e) { send({evt: 'tracer-error', arg0: '' + e, bt: []}); }
"""

def _display_width(text: str) -> int:
    """按终端/文本控件常见的东亚宽字符规则计算显示列数。"""
    import unicodedata
    return sum(2 if unicodedata.east_asian_width(ch) in ("F", "W", "A") else 1
               for ch in text)


def _pad_display(text: str, width: int) -> str:
    return text + " " * max(0, width - _display_width(text))


NAME_COL = 116          # 名称列固定宽度，保证 Lv / HP 起列一致
ROW_H = 15
BLOCK_TOP = 20
BLOCK_BOT = 6
BOARD_GAP = 10
BOARD_BORDER = 2


class PetPanel(ttk.Frame):
    """宠物栏：5 行固定显示 K0~K4。

    显示原则（UI宠物栏.md §7.1）：**不显示 K0/K1/... 这些协议槽位**——
    那是协议内部字段，不属于玩家信息；空槽只显示「空」。
    """

    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        ttk.Label(self, text="宠物栏",
                  font=("Microsoft YaHei", 9, "bold")).pack(anchor="w")
        ttk.Separator(self, orient="horizontal").pack(fill="x", pady=(0, 4))
        # （说明行已按 UI 瘦身文档 §8.2 删除，仅保留注释：）
        # 只有「完整宠物列表」（>=22 段的长包）才带名字和等级，服务器一般在
        # 进世界 / 宠物变动 / 抓到新宠时才下发，中间只有紧凑包，
        # 所以空槽显示「空」、短包期间显示「同步中…」都属正常，不是卡住。
        self.rows = []
        for _ in PET_SLOTS:
            v = tk.StringVar(value="空")
            lbl = ttk.Label(self, textvariable=v, width=22, anchor="w",
                            foreground="#95a5a6")
            lbl.pack(anchor="w")
            self.rows.append((v, lbl))

    def update_pet_list(self, pets):
        """pets: [pet|None] × 5，pet = {name,level,full,...}（v2 文档 §7）"""
        for i, (v, lbl) in enumerate(self.rows):
            p = pets[i] if i < len(pets) else None
            if not p:
                v.set("空")
                lbl.configure(foreground="#95a5a6")
                continue
            lv = p.get("level")
            if lv is None:
                # 只收到过短包（紧凑更新，没有等级/名字），等下一次长包
                v.set("同步中…")
                lbl.configure(foreground="#95a5a6")
                continue
            txt = f"{p.get('name') or '宠物'} Lv{lv}"
            if p.get("full"):
                txt += " ★满档"
                lbl.configure(foreground="#27ae60")
            else:
                lbl.configure(foreground="#34495e")
            v.set(txt)


class BattleBoard(tk.Canvas):
    """仿 STW 的固定战斗显示区。

    布局：整块区域左半=敌方标红，右半=我方标绿；两侧都按固定槽位排放，
    不再做「上下两块」——下块（我方后排）在实测里一直为空，已移除。
    槽位规则（来自 STW 界面约定）：
      我方（右，绿）: [0]=角色+骑宠合并一行，[5]=战宠石龟(min-1)
      敌方（左，红）: 空位从 [15] 开始排
    没有花哨血条，只有名称/等级/HP。
    """

    def __init__(self, master, width=780, height=175, **kw):
        super().__init__(master, width=width, height=height, bg="#ffffff",
                         highlightthickness=1, highlightbackground="#9aa0a6",
                         **kw)
        self.board_w = width
        self.board_h = height
        self.enemy = []      # [(slot, name, lv, hp, hpmax)]
        self.ally = []
        self.redraw()

    def set_units(self, enemy, ally):
        """enemy/ally: [(slot, name, lv, cur, max)]，slot 为显示槽位编号。"""
        self.enemy = list(enemy)
        self.ally = list(ally)
        self.redraw()

    def clear(self):
        self.enemy, self.ally = [], []
        self.redraw()

    def redraw(self):
        self.delete("all")
        mid = self.board_w // 2
        b = BOARD_BORDER
        # 左红右绿：整块高度不再切上下两块
        self.create_rectangle(b, b, mid - 2, self.board_h - b, outline="#c0392b")
        self.create_rectangle(mid + 2, b, self.board_w - b, self.board_h - b,
                              outline="#27ae60")
        self.create_text(b + 6, b + 4, anchor="w", text="敌方 ENEMY",
                         font=("Microsoft YaHei UI", 8), fill="#c0392b")
        self.create_text(mid + 8, b + 4, anchor="w", text="我方 ALLY",
                         font=("Microsoft YaHei UI", 8), fill="#27ae60")
        self._draw_side(self.enemy, b + 6)
        self._draw_side(self.ally, mid + 8)

    def _draw_side(self, rows, ox):
        for i, row in enumerate(rows[:SLOT_ROWS]):
            slot, name, lv, cur, mx = row[:5]
            extra = row[5] if len(row) > 5 else ""   # 附加血量（如骑宠 HP）
            y = BLOCK_TOP + ROW_H // 2 + i * ROW_H
            dead = mx and cur <= 0
            fg = "#95a5a6" if dead else "#2c3e50"
            nm = name if len(name) <= 12 else name[:11] + "…"
            # 槽位按协议用十六进制显示（敌方是 F/10/11/12/13，不是 15/16/17）
            self.create_text(ox, y, anchor="w", text=f"[{slot:X}]",
                             font=("Consolas", 9), fill="#7f8c8d")
            self.create_text(ox + 30, y, anchor="w", text=nm,
                             font=("Microsoft YaHei UI", 9), fill=fg)
            self.create_text(ox + 30 + NAME_COL, y, anchor="w", text=f"Lv{lv}",
                             font=("Consolas", 9), fill=fg)
            self.create_text(ox + 30 + NAME_COL + 44, y, anchor="w",
                             text=f"({cur}/{mx})", font=("Consolas", 9),
                             fill="#c0392b" if dead else "#2c3e50")
            if extra:
                self.create_text(ox + 30 + NAME_COL + 44 + 76, y, anchor="w",
                                 text=extra, font=("Consolas", 9),
                                 fill="#7f8c8d")

def fmt_units(units, player=None):
    """紧凑文本格式。敌我按 slot 判定，槽位用十六进制显示。"""
    enemy, ally = units_to_slots(units, player)
    out = []
    for slot, nm, lv, hp, hpmax in ally:
        out.append(f"   我方 [0x{slot:X}] {nm} Lv{lv} HP {hp}/{hpmax}")
    for slot, nm, lv, hp, hpmax in enemy:
        out.append(f"   敌方 [0x{slot:X}] {nm} Lv{lv} HP {hp}/{hpmax}")
    return out


def fmt_battle_roster(units, player=None):
    """文本版对阵表（战斗面板用 BattleBoard，这个是给日志用的）。"""
    enemy, ally = units_to_slots(units, player)

    def row(slot, name, lv, hp, hpmax):
        mark = "*" if hp <= 0 else " "
        return (f"{mark}[0x{slot:X}] {_pad_display(name, 18)} "
                f"Lv:{lv:<3} ({hp}/{hpmax})").rstrip()

    lines = ["敌方"]
    lines.extend(row(*r[:5]) for r in enemy)
    if not enemy:
        lines.append("  （暂无战斗数据）")
    lines.append("")
    lines.append("我方")
    lines.extend(row(*r[:5]) for r in ally)
    if not ally:
        lines.append("  （暂无战斗数据）")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 启动 / 监听：拉起游戏 -> 扫账号 -> 等登入
# ---------------------------------------------------------------------------
class Tracer(threading.Thread):
    """（已停用）挂到游戏进程上抓"谁让它退出"。

    ⚠ 停用原因：它会在启动时就往游戏里注入 frida。而游戏在「进入世界
    (state→9)」的瞬间做一次性注入扫描——那一刻进程里有 frida agent 的话，
    游戏会自尽并顺手杀掉注入宿主（我们的控制台），表现就是"一到 9 控制台
    闪退、游戏也没了"。之前 120s/8 场能活，是因为 frida 是进地图之后才挂的。
    留这个类只为记录机制，别再在进世界之前调用它。
    """

    def __init__(self, pid, q):
        super().__init__(daemon=True)
        self.pid, self.q = pid, q
        self.stop_flag = threading.Event()
        self.sess = None

    def on_msg(self, m, d):
        p = m.get("payload") or {}
        evt = p.get("evt")
        if evt in ("tracer-ready", "tracer-error"):
            self.q.put(("log", "sys" if evt == "tracer-ready" else "warn",
                        f"退出诊断：{evt} {p.get('arg0', '')}"))
            return
        bt = p.get("bt") or []
        self.q.put(("log", "warn", f"!! 游戏调用 {evt}（参数 {p.get('arg0')}）"))
        for i, fr in enumerate(bt[:12]):
            self.q.put(("log", "warn", f"      #{i} {fr}"))

    def run(self):
        for _ in range(60):
            try:
                self.sess = frida.attach(self.pid)
                break
            except Exception:
                time.sleep(0.5)
        if not self.sess:
            self.q.put(("log", "warn", "退出诊断：无法附加到游戏进程"))
            return
        try:
            sc = self.sess.create_script(TRACE_JS)
            sc.on("message", self.on_msg)
            sc.load()
        except Exception as e:
            self.q.put(("log", "warn", f"退出诊断挂载失败：{e}"))
            return
        while not self.stop_flag.is_set():
            time.sleep(0.5)
        try:
            sc.unload()
            self.sess.detach()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 引擎（后台线程）——已整体剥离到 stw_engine.py，本文件只 import 使用。
# Engine 独占的 helper（enc / HOOK / _is_name / fmt_damage / sa codec）一并
# 迁走了：它们若留在 stw_ui，会形成 stw_engine -> stw_ui 的循环 import。
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 界面
# ---------------------------------------------------------------------------
class App(tk.Tk):
    TAGS = {
        "sys":    "#4a90d9",
        "warn":   "#d98a2b",
        "battle": "#c0392b",
        "unit":   "#2c3e50",
        "act":    "#8e44ad",
        "hit":    "#e67e22",
        "ok":     "#27ae60",
        "map":    "#16a085",
        "dim":    "#95a5a6",
    }

    def __init__(self):
        super().__init__()
        self.title("石器时代 快速战斗控制台（原型）")
        self.geometry("1000x900")
        # 文档 §17 Step 7：低分辨率电脑别被截断
        self.minsize(920, 700)
        # ⚠ UI 事件队列协议已冻结（v2.1 §9）：消息 (kind, ...) 只有这 18 种：
        # log / phase / state / account / ready / dead / hook_state / auto_state /
        # stop_phase / battle_units / catch_match / catch_stat / pet_panel /
        # map_objects / stat / speed / fatal / done。
        # 后续只允许增版本，不许拆 Engine 时边改消息形状。战斗文字统一走
        # ("log", "battle", text)——旧 battle_header / battle_status 已删
        # （UI 从来不消费它们）。
        self.q = queue.Queue()
        self.cfg = {"pid": 0, "account": "", "accounts": [],
                    "fast_enc": True, "fast_battle": True,
                    "mode": "catch", "interval": 0.1, "secs": 36000.0,   #用户自己改的36000
                    "auto_start": True,
                    "maxb": 9999, "show46": False, "showraw": False}
        # 抓宠配置（文档 §27.1）：规则库 + 策略，统一挂在 cfg["catch"]
        self.catch_rules = load_catch_rules()
        self.cfg["catch"] = {
            "rules": self.catch_rules,
            "no_match_action": "flee",     # flee / attack / silent
            "pet_action": "attack",        # attack（真实抓包）/ wait（实验）
            "after_success": "continue",   # continue / stop / count
            "stop_count": 1,
        }
        self.eng = None
        self.watcher = None
        self.ready = False
        self.hook_ready = False     # 战斗监听是否已挂载（进 state9 自动挂）
        self.auto_exec = False      # 自动执行是否已开启（点按钮才开）
        self.stop_phase = STOPPED_READY   # 停止流程状态（RUNNING/…/STOPPED_READY）
        self._mode_user_set = False  # 用户手动选过策略就别再强制默认逃跑
        self._spd_pid = 0          # 已经打过加速补丁的 PID，防止重复打
        self._was_ready = False    # 只有真正连上过一次，才允许"游戏退出自动关控制台"
        self._closing = False
        self._sup_last = 0.0
        self._build()
        self.after(120, self._drain)
        self._poll_supervisor()

    def _poll_supervisor(self):
        """supervisor 轮询已停用。

        之前用它解耦"游戏/控制台生命周期"，但用户实测证明控制台直拉并不会被
        连带退出，        且它会与 Watcher 抢同一个游戏 PID（两边都改 ready/PID），
        导致界面状态冲突。现改回直拉单一路径，此处保留空转以兼容旧调用。
        """
        self.after(1000, self._poll_supervisor)

    def _build(self):
        """UI 瘦身版：按「连接 / 功能 / 抓宠 / 状态 / 战斗 / 日志 / 底部」分块。

        拆成子函数只为好定位，不改任何控件变量名与绑定
        （《UI界面瘦身更新文档》§11 / §12）。
        """
        self._build_connection_panel()
        self._build_option_panel()
        self._build_catch_panel()          # 抓宠规则库（左右并排）
        self._build_status_panel()
        self._build_battle_panel()
        self._build_log_panel()
        self._build_bottom_bar()

        # 控制台不许自己消失：回调异常只记不抛，关窗要确认
        self.report_callback_exception = self._tk_error
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._set_enabled(False)
        if "--launch" in sys.argv:          # 开屏自动拉起游戏，省得再点一次
            self.after(800, self._launch)

    # ------------------------------------------------------------------
    # 第一块：连接游戏（3 行）
    # ------------------------------------------------------------------
    def _build_connection_panel(self):
        lf = ttk.LabelFrame(self, text="第一步：连接游戏", padding=6)
        lf.pack(fill="x", padx=8, pady=(8, 3))

        # 第 1 行：主要操作
        r1 = ttk.Frame(lf)
        r1.pack(fill="x")
        self.btn_launch = ttk.Button(r1, text="连接 / 启动", command=self._launch)
        self.btn_launch.pack(side="left")
        self.v_exist = tk.BooleanVar(value=False)
        self.w_exist = ttk.Checkbutton(r1, text="游戏已手动打开",
                                       variable=self.v_exist)
        self.w_exist.pack(side="left", padx=(8, 12))
        ttk.Label(r1, text="账号:").pack(side="left")
        self.v_acct = tk.StringVar(value="")
        self.cb_acct = ttk.Combobox(r1, textvariable=self.v_acct, width=14,
                                    state="disabled")
        self.cb_acct.pack(side="left")
        self.cb_acct.bind("<<ComboboxSelected>>", self._sync)
        ttk.Label(r1, text="客户端:").pack(side="left", padx=(10, 0))
        self.v_pid = tk.StringVar(value="")
        self.cb_pid = ttk.Combobox(r1, textvariable=self.v_pid, width=42,
                                   state="readonly")
        self.cb_pid.pack(side="left")
        ttk.Button(r1, text="刷新", command=self._refresh).pack(side="left",
                                                                padx=(6, 0))
        self.clients = []
        self.after(400, self._refresh)

        # 第 2 行：启动参数（长输入框交给列自动伸缩，不再写死 width=88）
        r2 = ttk.Frame(lf)
        r2.pack(fill="x", pady=(3, 0))
        ttk.Label(r2, text="启动参数:").pack(side="left")
        self.v_args = tk.StringVar(value=GAME_ARGS)
        ttk.Entry(r2, textvariable=self.v_args).pack(side="left", fill="x",
                                                     expand=True, padx=(4, 0))

        # 第 3 行：连接状态 + 工作目录（只显示路径本身）
        # ⚠ 「工作目录必须是 D:\zcgd2.5(new)，否则 0xC0000005 崩」是开发注意，
        #    按文档 §4.4 从 UI 移除，保留在代码注释里：GAME_CWD 见 stw_config。
        r3 = ttk.Frame(lf)
        r3.pack(fill="x", pady=(3, 0))
        self.v_phase = tk.StringVar(value="未连接 — 点「连接 / 启动」")
        ttk.Label(r3, textvariable=self.v_phase,
                  foreground="#c0392b").pack(side="left")
        ttk.Label(r3, text=f"工作目录：{GAME_CWD}",
                  foreground="#7f8c8d").pack(side="right")

    # ------------------------------------------------------------------
    # 第二块：功能设置（严格 3 行）
    # ------------------------------------------------------------------
    def _build_option_panel(self):
        self.opts = ttk.LabelFrame(self, text="第二步：功能设置", padding=6)
        self.opts.pack(fill="x", padx=8, pady=(3, 3))
        self.v_enc = tk.BooleanVar(value=True)
        self.v_bat = tk.BooleanVar(value=True)
        self.v_mode = tk.StringVar(value="catch")
        self.v_iv = tk.StringVar(value="0.1")
        self.v_maxb = tk.StringVar(value="9999")
        self.v_46 = tk.BooleanVar(value=False)
        self.v_raw = tk.BooleanVar(value=False)

        # 第 1 行：核心战斗功能
        r1 = ttk.Frame(self.opts)
        r1.pack(fill="x")
        self.w_enc = ttk.Checkbutton(r1, text="快速遇敌", variable=self.v_enc,
                                     command=self._sync)
        self.w_enc.pack(side="left")
        self.w_bat = ttk.Checkbutton(r1, text="快速战斗", variable=self.v_bat,
                                     command=self._sync)
        self.w_bat.pack(side="left", padx=(10, 0))
        ttk.Label(r1, text="  战斗指令:").pack(side="left")
        self.w_flee = ttk.Radiobutton(r1, text="逃跑", value="flee",
                                      variable=self.v_mode,
                                      command=self._pick_mode)
        self.w_flee.pack(side="left")
        self.w_atk = ttk.Radiobutton(r1, text="攻击", value="attack",
                                     variable=self.v_mode,
                                     command=self._pick_mode)
        self.w_atk.pack(side="left")
        self.w_catch = ttk.Radiobutton(r1, text="抓宠", value="catch",
                                       variable=self.v_mode,
                                       command=self._pick_mode)
        self.w_catch.pack(side="left")

        # 第 2 行：运行参数 + 加速
        r2 = ttk.Frame(self.opts)
        r2.pack(fill="x", pady=(3, 0))
        ttk.Label(r2, text="走位间隔(s):").pack(side="left")
        self.w_iv = ttk.Entry(r2, textvariable=self.v_iv, width=6)
        self.w_iv.pack(side="left")
        ttk.Label(r2, text="最多场数:").pack(side="left", padx=(10, 0))
        self.w_maxb = ttk.Entry(r2, textvariable=self.v_maxb, width=6)
        self.w_maxb.pack(side="left")
        # 进地图(state=9)后自动开启加速移动（move+ui 共 21 个补丁）
        self.v_auto = tk.BooleanVar(value=True)
        self.w_auto = ttk.Checkbutton(r2, text="自动开启加速移动",
                                      variable=self.v_auto, command=self._sync)
        self.w_auto.pack(side="left", padx=(12, 0))
        self.v_spd = tk.BooleanVar(value=False)
        self.w_spd = ttk.Checkbutton(r2, text="加速移动",   # STW move+ui 21 补丁
                                     variable=self.v_spd, command=self._on_speed)
        self.w_spd.pack(side="left", padx=(10, 0))
        self.btn_spdchk = ttk.Button(r2, text="检查状态",
                                     command=self._check_speed)
        self.btn_spdchk.pack(side="left", padx=(10, 0))

        # 第 3 行：低频 / 调试项
        r3 = ttk.Frame(self.opts)
        r3.pack(fill="x", pady=(3, 0))
        self.v_close = tk.BooleanVar(value=True)
        self.w_close = ttk.Checkbutton(r3, text="游戏退出时关闭控制台",
                                       variable=self.v_close, command=self._sync)
        self.w_close.pack(side="left")
        ttk.Label(r3, text="  调试:", foreground="#7f8c8d").pack(side="left")
        self.w_46 = ttk.Checkbutton(r3, text="fid=46 单位更新",
                                    variable=self.v_46, command=self._sync)
        self.w_46.pack(side="left")
        self.w_raw = ttk.Checkbutton(r3, text="其它原始包",
                                     variable=self.v_raw, command=self._sync)
        self.w_raw.pack(side="left", padx=(8, 0))

        # ⚠ opt_widgets 是 _set_enabled() 批量启停的名单，必须保留原有集合。
        #   w_auto / w_close / btn_spdchk 原本就不在里面（纯本地设置），
        #   按文档 §5.4「不确定就不要扩张改动范围」，本次不扩大名单。
        self.opt_widgets = [self.w_enc, self.w_bat, self.w_flee, self.w_atk,
                            self.w_catch, self.w_iv, self.w_maxb, self.w_46,
                            self.w_raw, self.w_spd]

    # ------------------------------------------------------------------
    # 状态条（1~2 行，不再做成小卡片）
    # ------------------------------------------------------------------
    def _build_status_panel(self):
        st = ttk.Frame(self, padding=(8, 2))
        st.pack(fill="x", padx=8, pady=(3, 0))
        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=8)
        self.v_state = tk.StringVar(value="-")
        self.v_pos = tk.StringVar(value="-")
        self.v_cnt = tk.StringVar(value="战斗 0 / 遇敌包 0 / fid=14 0 / fid=43 0")
        r1 = ttk.Frame(st)
        r1.pack(fill="x")
        ttk.Label(r1, textvariable=self.v_state, width=18).pack(side="left")
        ttk.Label(r1, textvariable=self.v_pos).pack(side="left", padx=(8, 0))
        ttk.Label(r1, textvariable=self.v_cnt).pack(side="left", padx=(8, 0))
        # 停止后用来确认「地图里的 NPC 有没有刷出来」
        self.v_npc = tk.StringVar(value="地图/NPC：—")
        ttk.Label(st, textvariable=self.v_npc,
                  foreground="#16a085").pack(anchor="w")

    # ------------------------------------------------------------------
    # 战斗显示区（视觉中心，不做压缩）
    # ------------------------------------------------------------------
    def _build_battle_panel(self):
        lf2 = ttk.LabelFrame(self, text="战斗", padding=6)
        lf2.pack(fill="x", padx=8, pady=(3, 3))
        mid = ttk.Frame(lf2)
        mid.pack(fill="x")
        self.board = BattleBoard(mid, width=760, height=175)
        self.board.pack(side="left")
        self.pets = PetPanel(mid)          # 宠物栏（K0~K4，隐藏协议槽位）
        self.pets.pack(side="left", padx=(14, 0), anchor="n")
        self.v_round = tk.StringVar(value="回合 —")
        ttk.Label(lf2, textvariable=self.v_round,
                  foreground="#34495e").pack(anchor="w")

    # ------------------------------------------------------------------
    # 原始日志：真正可折叠（默认收起，self.txt 永不销毁）
    # ------------------------------------------------------------------
    def _build_log_panel(self):
        log_wrap = ttk.Frame(self)
        log_wrap.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self.log_expanded = tk.BooleanVar(value=False)
        self.btn_log_toggle = ttk.Button(
            log_wrap, text="▶ 原始日志（调试用）",
            command=self._toggle_log_panel)
        self.btn_log_toggle.pack(anchor="w")
        self.log_body = ttk.Frame(log_wrap)
        # ⚠ 默认不要 pack(self.log_body)：收起 = pack_forget，
        #   绝不 destroy —— 后台一直在往 self.txt 里写日志。
        self.txt = scrolledtext.ScrolledText(self.log_body, height=8,
                                             font=("Consolas", 9),
                                             state="disabled")
        self.txt.pack(fill="both", expand=True)
        for k, c in self.TAGS.items():
            self.txt.tag_config(k, foreground=c)
        self.txt.tag_config("battle", font=("Consolas", 9, "bold"))

    def _toggle_log_panel(self):
        on = not self.log_expanded.get()
        self.log_expanded.set(on)
        if on:
            self.btn_log_toggle.configure(text="▼ 原始日志（调试用）")
            self.log_body.pack(fill="both", expand=True, pady=(4, 0))
        else:
            self.btn_log_toggle.configure(text="▶ 原始日志（调试用）")
            self.log_body.pack_forget()

    # ------------------------------------------------------------------
    # 底部操作栏
    # ------------------------------------------------------------------
    def _build_bottom_bar(self):
        bot = ttk.Frame(self, padding=8)
        bot.pack(fill="x")
        # 按钮只管「自动执行」的开/关；战斗监听进 state9 就自动挂上，
        # 与按钮无关（文档：Hook 战斗界面 与 执行战斗策略 解耦）
        self.btn = ttk.Button(bot, text="开始自动战斗", command=self._toggle,
                              state="disabled")
        self.btn.pack(side="left")
        ttk.Button(bot, text="清空日志", command=self._clear).pack(side="left",
                                                                   padx=6)
        # 自动执行紧挨按钮（它与主按钮直接相关），监听状态排在其后
        # 注意别叫 v_auto：那个名字已经被「自动开启加速移动」占用了
        self.v_exec = tk.StringVar(value="自动执行：关")
        self.lbl_exec = ttk.Label(bot, textvariable=self.v_exec,
                                  foreground="#95a5a6")
        self.lbl_exec.pack(side="left", padx=(10, 0))
        self.v_hook = tk.StringVar(value="战斗监听：未挂载")
        self.lbl_hook = ttk.Label(bot, textvariable=self.v_hook,
                                  foreground="#95a5a6")
        self.lbl_hook.pack(side="left", padx=(10, 0))
        self.v_hint = tk.StringVar(value="")     # 临时提示放中间
        ttk.Label(bot, textvariable=self.v_hint,
                  foreground="#d98a2b").pack(side="left", padx=(10, 0))
        self.v_alive = tk.StringVar(value="● 控制台运行中")
        ttk.Label(bot, textvariable=self.v_alive,
                  foreground="#27ae60").pack(side="right")

    def _set_enabled(self, on):
        for w in self.opt_widgets:
            w.configure(state="normal" if on else "disabled")
        # 按钮控制的是「自动执行」，必须等战斗监听真的挂上才可点
        self.btn.configure(state="normal" if (on and self.hook_ready)
                           else "disabled")

    # ---- 交互 ----
    def _refresh(self):
        try:
            rows = list_clients()
        except Exception as e:
            self._put("warn", f"列进程失败：{e}")
            return
        self.clients = rows
        vals = [fmt_client(r) for r in rows]
        self.cb_pid.configure(values=vals)
        ok = [r for r in rows if not r["blocked"]]
        if vals:
            self.cb_pid.current(vals.index(fmt_client(ok[0])) if ok else 0)
        self._put("dim", f"现有 sa_2903.exe：{[r['pid'] for r in rows] or '无'}；"
                         f"可操作 {[r['pid'] for r in ok] or '无'}")

    def _tk_error(self, exc, val, tb):
        msg = "".join(traceback.format_exception(exc, val, tb))
        self._put("warn", "界面回调异常（控制台不会退出）：\n" + msg[-800:])

    def _on_close(self):
        if self.eng and self.eng.is_alive():
            if messagebox.askokcancel(
                    "退出", "引擎还在跑，确定退出？\n（游戏不会被关掉，只是停止代打）"):
                self.eng.stop_flag.set()
                self.v_hint.set("正在收尾…")
                self.after(1500, self._hard_destroy)
            return
        if messagebox.askokcancel("退出", "关闭控制台？\n（游戏不受影响，会继续运行）"):
            self._hard_destroy()

    def _auto_close(self):
        """游戏进程没了 -> 控制台跟着退出（勾选「自动退出」时）。"""
        if getattr(self, "_closing", False):
            return
        self._closing = True
        self._put("sys", "游戏已退出，控制台 1.5 秒后自动关闭")
        self.v_phase.set("游戏已退出 — 控制台即将关闭")
        if self.eng and self.eng.is_alive():
            self.eng.stop_flag.set()
        self.after(1500, self._hard_destroy)

    def _hard_destroy(self):
        """收尾：停引擎、停监视线程、收掉独立读取进程，再关窗口。"""
        try:
            if self.eng and self.eng.is_alive():
                self.eng.stop_flag.set()
                self.eng.join(timeout=1.0)
        except Exception:
            pass
        try:
            if self.watcher is not None:
                self.watcher.stop_flag.set()
                rp = getattr(self.watcher, "reader_proc", None)
                if rp is not None and rp.poll() is None:
                    rp.terminate()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass
        try:
            self.quit()
        except Exception:
            pass

    def _launch(self):
        """点「启动游戏」：控制台直接用 Popen 拉起游戏。

        用户实测反驳了「控制台 Tk 会被游戏连带退出」的假设——STW 拉 sa.exe 也
        不会被干掉，控制台同理。所以这里恢复直拉：控制台拿得到 PID、能看到
        窗口、不再经由 supervisor 绕路。
        """
        # 防重入：拉起过程较慢，连点/自动重试会导致同一秒开出两个游戏进程
        # （实测 PID 25068 与 55852 同秒出现），进而引发布局与监听混乱
        if getattr(self, "_launching", False):
            self._put("dim", "上一次启动还没结束，忽略本次点击")
            return
        if self.watcher and self.watcher.is_alive():
            return
        self._launching = True
        self.btn_launch.configure(state="disabled")
        try:
            self._launch_inner()
        finally:
            self._launching = False
            self.btn_launch.configure(state="normal")

    def _launch_inner(self):
        launched = 0          # 0=本次没有新拉起（附加模式），Watcher 就不会重复启动
        if self.v_exist.get():
            self.v_phase.set("正在附加…")
            if not self.clients:
                self._refresh()
            i = self.cb_pid.current()
            if i < 0 or i >= len(self.clients):
                self._put("warn", "先在下拉框里选一个客户端")
                self.btn_launch.configure(state="normal")
                return
            r = self.clients[i]
            if r["blocked"]:
                messagebox.showerror(
                    "拒绝操作",
                    f"PID {r['pid']} 是 STW0.30.exe 拉起来的客户端，按约定不能碰。")
                self.btn_launch.configure(state="normal")
                return
            pid = r["pid"]
        else:
            self.v_phase.set("正在启动 sa_2903.exe …")
            self._put("sys", f"命令行：{GAME_EXE} {self.v_args.get()}")
            self._put("sys", f"工作目录：{GAME_CWD}")
            try:
                # 用 cmd /c start：控制台发起，但游戏归 explorer 管，
                # 控制台不再是父进程（实测父进程会在进世界时被游戏杀掉）
                pid = launch_game_detached(GAME_EXE, self.v_args.get(),
                                           GAME_CWD)
                how = "外部拉起(explorer 为父进程，控制台非父进程)"
                proc = None
                if not pid:
                    self._put("warn", "启动了但 25s 内没发现新的 sa_2903.exe")
                    self.btn_launch.configure(state="normal")
                    return
            except Exception as e:
                self._put("warn", f"启动失败：{type(e).__name__}: {e}")
                self.btn_launch.configure(state="normal")
                return
            self._put("sys", f"已拉起游戏 PID={pid} 方式={how}")
            # 把已拉起的 PID 交给 Watcher 复用；不传的话 Watcher 会再拉一个，
            # 一次点击就开出两个 sa_2903.exe（51536 / 56904 同秒）
            launched = pid
        self.watcher = Watcher(self.q, attach_existing=self.v_exist.get(),
                               args=self.v_args.get(), pid=pid,
                               launched_pid=launched)
        self.watcher.start()
        self.btn_launch.configure(state="normal")

    def _sync(self):
        self.cfg.update(fast_enc=self.v_enc.get(), fast_battle=self.v_bat.get(),
                        mode=self.v_mode.get(), show46=self.v_46.get(),
                        showraw=self.v_raw.get(), account=self.v_acct.get())
        self.cfg["auto_close"] = self.v_close.get()
        self.cfg["auto_start"] = self.v_auto.get()
        self.cfg["speed"] = self.v_spd.get()
        try:
            self.cfg["interval"] = float(self.v_iv.get())
        except ValueError:
            self.cfg["interval"] = 0.1
        try:
            self.cfg["maxb"] = int(self.v_maxb.get())
        except ValueError:
            self.cfg["maxb"] = 9999
        # 抓宠策略（文档 §27.1），规则库对象直接共享给引擎
        c = self.cfg.setdefault("catch", {})
        c["rules"] = getattr(self, "catch_rules", {})
        if hasattr(self, "v_nomatch"):
            c["no_match_action"] = self.v_nomatch.get()
            c["pet_action"] = self.v_petact.get()
            c["after_success"] = self.v_after.get()
            try:
                c["stop_count"] = int(self.v_stopn.get())
            except ValueError:
                c["stop_count"] = 1
            c["drop_non_full"] = bool(self.v_dropnf.get())
        # 上毒（抓宠前）：数值型配置容错 —— 用户手输错就退回默认，不让引擎崩
        if hasattr(self, "v_poison"):
            c["poison_enabled"] = bool(self.v_poison.get())
            try:
                c["poison_skill"] = max(0, int(self.v_pskill.get()))
            except ValueError:
                c["poison_skill"] = 2
            try:
                r = float(self.v_pratio.get())
                c["poison_hp_ratio"] = r if 0.01 <= r <= 0.99 else 0.10
            except ValueError:
                c["poison_hp_ratio"] = 0.10
            c["poison_verify"] = self.v_pverify.get()
            if c["poison_verify"] not in POISON_VERIFY_MODES:
                c["poison_verify"] = "strict"
            c["poison_dmg_mode"] = self.v_pdmg.get()
            if c["poison_dmg_mode"] not in POISON_DMG_MODES:
                c["poison_dmg_mode"] = "derived"
        self._apply_catch_enabled()

    # ------------------------------------------------------------------
    # 抓宠 UI（规则库 + 策略 + 当前战斗匹配预览 + 统计）
    # ------------------------------------------------------------------
    def _build_catch_panel(self):
        """左右并排：左=规则列表+管理按钮，右=策略设置+统计。

        《UI界面瘦身更新文档》§6：整体高度主要由左侧 Treeview 的 height=5 决定，
        右侧不再向下堆叠。只改排版与文案，变量名 / value / 配置语义一律不动。
        """
        self.lf_catch = ttk.LabelFrame(
            self, text="抓宠规则库（仅「抓宠」模式生效）", padding=6)
        self.lf_catch.pack(fill="x", padx=8, pady=(0, 3))

        body = ttk.Frame(self.lf_catch)
        body.pack(fill="x")
        # 左 : 右 ≈ 3 : 2（约 60% / 40%）
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)

        # ================= 左：规则列表 + 管理按钮 =================
        left = ttk.Frame(body)
        left.grid(row=0, column=0, sticky="nsew")

        cols = ("on", "name", "lvmin", "lvmax", "lvn", "hpn")
        self.tv_rules = ttk.Treeview(left, columns=cols, height=5,
                                     show="headings")
        for c, w, t in (("on", 42, "启用"), ("name", 125, "目标名称"),
                        ("lvmin", 48, "最低"), ("lvmax", 48, "最高"),
                        ("lvn", 54, "等级数"), ("hpn", 54, "HP数")):
            self.tv_rules.heading(c, text=t)
            # 只让「目标名称」吃掉多出来的宽度：否则列宽合计 ~371 而控件宽 ~590，
            # 右侧会空出一大块难看的留白（左栏是 fill="x" 的）。
            self.tv_rules.column(c, width=w, anchor="center",
                                 stretch=(c == "name"))
        self.tv_rules.pack(fill="x")
        self.tv_rules.bind("<Double-1>", lambda e: self._edit_rule())

        br = ttk.Frame(left)
        br.pack(fill="x", pady=(3, 0))
        for txt, cmd in (("新增规则", self._new_rule),
                         ("编辑规则", self._edit_rule),
                         ("删除规则", self._del_rule),
                         ("启用/禁用", self._toggle_rule),
                         ("批量导入", self._import_rules),
                         ("载入示例", self._load_sample)):
            ttk.Button(br, text=txt, command=cmd).pack(side="left", padx=2)

        # ================= 右：策略设置（紧凑 5 行）=================
        right = ttk.Frame(body)
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.v_nomatch = tk.StringVar(value="flee")
        self.v_petact = tk.StringVar(value="attack")
        self.v_after = tk.StringVar(value="continue")
        self.v_stopn = tk.StringVar(value="1")

        # 右 1：未命中 + 战宠
        r1 = ttk.Frame(right)
        r1.pack(fill="x")
        ttk.Label(r1, text="未命中:").pack(side="left")
        # value 仍是 flee / attack / silent，只缩显示文案
        for t, v in (("逃跑", "flee"), ("攻击", "attack"), ("静默", "silent")):
            ttk.Radiobutton(r1, text=t, value=v, variable=self.v_nomatch,
                            command=self._sync).pack(side="left")
        ttk.Label(r1, text="战宠:").pack(side="left", padx=(8, 0))
        # value 仍是 attack / wait（"跟随攻击(已抓包)" 缩成 "跟随"）
        for t, v in (("跟随", "attack"), ("待机", "wait")):
            ttk.Radiobutton(r1, text=t, value=v, variable=self.v_petact,
                            command=self._sync).pack(side="left")

        # 右 2：抓到后 —— 显示缩成「继续 / 抓1只后停 / 达到数量后停」，
        #        value 仍是 continue / stop / count（文档 §6.4 明确只改显示）
        r2 = ttk.Frame(right)
        r2.pack(fill="x", pady=(2, 0))
        ttk.Label(r2, text="抓到后:").pack(side="left")
        for t, v in (("继续", "continue"), ("抓1只后停", "stop"),
                     ("达到数量后停", "count")):
            ttk.Radiobutton(r2, text=t, value=v, variable=self.v_after,
                            command=self._sync).pack(side="left")
        ttk.Label(r2, text="数量:").pack(side="left", padx=(6, 0))
        ttk.Entry(r2, textvariable=self.v_stopn, width=4).pack(side="left")

        # 右 3：丢弃 + 上毒
        # 丢弃不满档（丢弃宠物.MD）：抓到的宠不是满档就发 fid=21 丢掉。
        # 只对新抓到的宠生效，已有宠不判满档、也绝不会被丢；
        # 以服务端 fid=46 回包为准，不本地预清（细节保留在注释，不再常驻 UI）。
        r3 = ttk.Frame(right)
        r3.pack(fill="x", pady=(2, 0))
        self.v_dropnf = tk.BooleanVar(value=False)
        ttk.Checkbutton(r3, text="非满档自动丢弃",
                        variable=self.v_dropnf,
                        command=self._sync).pack(side="left")
        # —— 抓宠前上毒（抓宠智能筛选逻辑开发文档 v2 §3~§9）——
        # 流程：等级/HP上限初筛 → 猛毒 J|格|目标 + 战宠待机 → 毒跳验证 → 控血 → 抓
        self.v_poison = tk.BooleanVar(value=True)
        ttk.Checkbutton(r3, text="抓宠前上毒", variable=self.v_poison,
                        command=self._sync).pack(side="left", padx=(8, 0))
        ttk.Label(r3, text="技能:").pack(side="left", padx=(6, 0))
        self.v_pskill = tk.StringVar(value="2")
        ttk.Entry(r3, textvariable=self.v_pskill, width=3).pack(side="left")
        ttk.Label(r3, text="控血:").pack(side="left", padx=(4, 0))
        self.v_pratio = tk.StringVar(value="0.10")
        ttk.Entry(r3, textvariable=self.v_pratio, width=5).pack(side="left")

        # 右 4：毒跳验证 + 毒伤口径
        # 三档说明（只控血不判满档 / 不通过也继续抓只记日志 / 不通过就换目标）
        # 原样保留在注释里，不再占主界面宽度。
        r4 = ttk.Frame(right)
        r4.pack(fill="x", pady=(2, 0))
        ttk.Label(r4, text="毒验:").pack(side="left")
        self.v_pverify = tk.StringVar(value="strict")
        for t, v in (("关", "off"), ("记录", "log"), ("严格", "strict")):
            ttk.Radiobutton(r4, text=t, value=v, variable=self.v_pverify,
                            command=self._sync).pack(side="left")
        ttk.Label(r4, text="口径:").pack(side="left", padx=(8, 0))
        self.v_pdmg = tk.StringVar(value="derived")
        # ⚠ 文案必须点明「体」是成长后的体力，不是 HP —— 早期就栽在这个误解上
        for t, v in (("成长四维", "derived"), ("原始四维", "base")):
            ttk.Radiobutton(r4, text=t, value=v, variable=self.v_pdmg,
                            command=self._sync).pack(side="left")

        # 右 5：抓宠统计（文案精简，字段仍是 hpmax_matched / poison_confirmed /
        #        no_match / dropped）
        # 当前战斗匹配仍在后台计算/记录，但按界面要求不再显示独立预览行。
        self.v_match = tk.StringVar(value="")
        self.v_cstat = tk.StringVar(
            value="统计：HP命中 0 / 毒确认 0 / 未命中 0 / 丢弃 0")
        ttk.Label(right, textvariable=self.v_cstat,
                  foreground="#8e44ad").pack(anchor="w", pady=(2, 0))

        self._refresh_rules()

    def _refresh_rules(self):
        for i in self.tv_rules.get_children():
            self.tv_rules.delete(i)
        for name, r in self.catch_rules.items():
            lvs = sorted((r.get("levels") or {}).keys())
            hpn = sum(len(((r["levels"][lv]).get("max_hp")) or set()) for lv in lvs)
            self.tv_rules.insert("", "end", iid=name, values=(
                "☑" if r.get("enabled", True) else "☐", name,
                lvs[0] if lvs else "-", lvs[-1] if lvs else "-",
                len(lvs), hpn))

    def _sel_rule(self):
        sel = self.tv_rules.selection()
        return sel[0] if sel else None

    def _save_rules(self):
        """规则改动落盘 + 同步给引擎（引擎读 cfg['catch']['rules'] 同一对象）。"""
        ok = save_catch_rules(self.catch_rules)
        self.cfg.setdefault("catch", {})["rules"] = self.catch_rules
        self._refresh_rules()
        self._sync()
        if not ok:
            self._put("warn", "抓宠规则保存失败（磁盘不可写？）")

    def _new_rule(self):
        self._rule_editor(None)

    def _edit_rule(self):
        name = self._sel_rule()
        if not name:
            self._put("warn", "抓宠规则：先在列表里选一条")
            return
        self._rule_editor(name)

    def _del_rule(self):
        name = self._sel_rule()
        if not name:
            return
        if not messagebox.askyesno("删除规则", f"确定删除「{name}」？"):
            return
        self.catch_rules.pop(name, None)
        self._save_rules()

    def _toggle_rule(self):
        name = self._sel_rule()
        if not name:
            return
        r = self.catch_rules[name]
        r["enabled"] = not r.get("enabled", True)
        self._save_rules()

    def _load_sample(self):
        try:
            rule = parse_catch_rule_text(CATCH_SAMPLE_TEXT)
        except Exception as e:
            self._put("warn", f"示例解析失败：{e}")
            return
        self.catch_rules[rule["name"]] = rule
        self._save_rules()
        self._put("sys", f"已载入示例规则：{rule['name']}"
                         f"（{len(rule['levels'])} 个等级）")

    def _rule_editor(self, name):
        """规则编辑窗口：等级 -> maxHP 白名单（每级数量不限）。"""
        rule = self.catch_rules.get(name) if name else None
        dlg = tk.Toplevel(self)
        dlg.title("抓宠规则编辑")
        dlg.geometry("680x480")
        dlg.transient(self)

        ttk.Label(dlg, text="目标名称:").grid(row=0, column=0, sticky="e",
                                             padx=4, pady=4)
        v_name = tk.StringVar(value=name or "")
        e_name = ttk.Entry(dlg, textvariable=v_name, width=26)
        e_name.grid(row=0, column=1, sticky="w")
        v_on = tk.BooleanVar(value=(rule or {}).get("enabled", True))
        ttk.Checkbutton(dlg, text="启用规则", variable=v_on).grid(
            row=0, column=2, sticky="w")

        hdr = ttk.Frame(dlg)
        hdr.grid(row=1, column=0, columnspan=3, sticky="w", padx=4)
        ttk.Label(hdr, text="等级", width=10).pack(side="left")
        ttk.Label(hdr, text="允许的 maxHP（逗号分隔，每级数量不限）").pack(side="left")

        rowsf = ttk.Frame(dlg)
        rowsf.grid(row=2, column=0, columnspan=3, sticky="nsew", padx=4)
        dlg.rowconfigure(2, weight=1)
        rows = []

        def add_row(lv=None, hps=None):
            r = len(rows)
            v_lv = tk.StringVar(value="" if lv is None else str(lv))
            v_hp = tk.StringVar(value="" if hps is None
                                else ",".join(str(x) for x in sorted(hps)))
            ttk.Entry(rowsf, textvariable=v_lv, width=10).grid(
                row=r, column=0, padx=2, pady=1)
            ttk.Entry(rowsf, textvariable=v_hp, width=74).grid(
                row=r, column=1, padx=2, pady=1)
            rows.append((v_lv, v_hp))

        if rule:
            for lv in sorted((rule.get("levels") or {}).keys()):
                add_row(lv, (rule["levels"][lv]).get("max_hp") or set())
        else:
            add_row()

        def del_row():
            if len(rows) <= 1:
                return
            rows.pop()
            for w in rowsf.grid_slaves(row=len(rows)):
                w.destroy()

        def save():
            nm = v_name.get().strip()
            if not nm:
                messagebox.showwarning("抓宠规则", "目标名称不能为空")
                return
            levels = {}
            for v_lv, v_hp in rows:
                s = v_lv.get().strip()
                if not s:
                    continue
                try:
                    lv = int(s)
                except ValueError:
                    messagebox.showwarning("抓宠规则", f"等级不是数字：{s}")
                    return
                if lv in levels:
                    messagebox.showwarning("抓宠规则", f"等级重复：Lv{lv}")
                    return
                hps = set()
                for x in v_hp.get().replace("，", ",").split(","):
                    x = x.strip()
                    if not x:
                        continue
                    try:
                        hps.add(int(x))
                    except ValueError:
                        messagebox.showwarning("抓宠规则",
                                               f"maxHP 不是数字：{x}")
                        return
                if not hps:
                    messagebox.showwarning(
                        "抓宠规则", f"Lv{lv} 至少要填写一个允许的 maxHP")
                    return
                levels[lv] = {"max_hp": hps}
            if not levels:
                messagebox.showwarning("抓宠规则", "至少要有一个等级")
                return

            # 编辑时允许改名，但必须把旧 key 一起移走；否则会残留两条规则。
            if name and nm != name and nm in self.catch_rules:
                if not messagebox.askyesno(
                        "抓宠规则", f"「{nm}」已存在，确定覆盖吗？"):
                    return
            old = self.catch_rules.get(name or nm) or self.catch_rules.get(nm) or {}
            self.catch_rules[nm] = {
                "enabled": v_on.get(), "levels": levels,
                "meta": old.get("meta", []),
                "level_extra": old.get("level_extra", {}),
            }
            if name and nm != name:
                self.catch_rules.pop(name, None)
            self._save_rules()
            self._put("sys", f"抓宠规则已保存：{nm}（{len(levels)} 个等级）")
            dlg.destroy()

        btns = ttk.Frame(dlg)
        btns.grid(row=3, column=0, columnspan=3, pady=6)
        ttk.Button(btns, text="+增加等级", command=lambda: add_row()).pack(
            side="left", padx=2)
        ttk.Button(btns, text="-删除等级", command=del_row).pack(side="left", padx=2)
        ttk.Button(btns, text="保存", command=save).pack(side="left", padx=14)
        ttk.Button(btns, text="取消", command=dlg.destroy).pack(side="left")

    def _import_rules(self):
        """批量导入：文本 -> 预览 -> 确认才写入（数据量很大，不能逐行填）。"""
        dlg = tk.Toplevel(self)
        dlg.title("批量导入抓宠规则")
        dlg.geometry("760x540")
        dlg.transient(self)
        ttk.Label(dlg, text="第1行 名字 / 第2行 meta / 第3行 level_extra / "
                            "第4行起 lv|maxHP").pack(anchor="w", padx=6, pady=4)
        txt = scrolledtext.ScrolledText(dlg, height=16, font=("Consolas", 9))
        txt.pack(fill="both", expand=True, padx=6)
        pv = tk.StringVar(value="")
        ttk.Label(dlg, textvariable=pv, justify="left",
                  wraplength=730).pack(anchor="w", padx=6, pady=4)
        parsed = {}

        def do_parse():
            nonlocal parsed
            try:
                parsed = parse_catch_rule_text(txt.get("1.0", "end"))
            except Exception as e:
                parsed = {}
                pv.set(f"解析失败：{e}")
                return
            lvs = sorted(parsed["levels"].keys())
            hpn = sum(len(parsed["levels"][lv]["max_hp"]) for lv in lvs)
            lines = [f"目标：{parsed['name']}",
                     f"等级数 {len(lvs)} · 最低 Lv{lvs[0]} · 最高 Lv{lvs[-1]} "
                     f"· maxHP 白名单总数 {hpn}"]
            for lv in lvs[:6]:
                hs = sorted(parsed["levels"][lv]["max_hp"])
                tail = "..." if len(hs) > 8 else ""
                lines.append("  Lv%d → %s%s" % (
                    lv, ",".join(str(x) for x in hs[:8]), tail))
            if len(lvs) > 6:
                lines.append("  ...")
            pv.set("\n".join(lines))

        def do_import():
            if not parsed:
                do_parse()
            if not parsed:
                return
            self.catch_rules[parsed["name"]] = parsed
            self._save_rules()
            self._put("sys", f"已导入规则：{parsed['name']}"
                             f"（{len(parsed['levels'])} 个等级）")
            dlg.destroy()

        bf = ttk.Frame(dlg)
        bf.pack(pady=6)
        ttk.Button(bf, text="解析", command=do_parse).pack(side="left", padx=4)
        ttk.Button(bf, text="导入规则", command=do_import).pack(side="left", padx=4)
        ttk.Button(bf, text="取消", command=dlg.destroy).pack(side="left", padx=4)

    def _apply_catch_enabled(self):
        """非「抓宠」模式时把整个抓宠面板置灰。"""
        if not hasattr(self, "lf_catch"):
            return
        on = (self.v_mode.get() == "catch")
        st = "normal" if on else "disabled"

        def walk(w):
            for c in w.winfo_children():
                try:
                    c.configure(state=st)
                except tk.TclError:
                    pass
                walk(c)

        walk(self.lf_catch)

    def _set_exec_label(self, phase, note=""):
        """底部「自动执行」标签：停止流程要让用户看见进度，别以为是卡死。"""
        MODE_TXT = {"attack": "攻击", "flee": "逃跑", "catch": "抓宠"}
        if phase == STOP_RUNNING:
            self.v_exec.set("自动执行：开 · "
                            + MODE_TXT.get(self.cfg.get("mode", "flee"), "?"))
            self.lbl_exec.configure(foreground="#27ae60")
        elif phase == STOP_PENDING:
            self.v_exec.set("自动执行：关 · ⌛ 等待战斗结束")
            self.lbl_exec.configure(foreground="#d98a2b")
        elif phase == MAP_SYNC_WAIT:
            self.v_exec.set("自动执行：关 · ⌛ 等待地图/NPC 同步"
                            + (f" {note}" if note else ""))
            self.lbl_exec.configure(foreground="#d98a2b")
        else:                                   # STOPPED_READY
            self.v_exec.set("自动执行：关 · ✓ 已停止，"
                            + (note or "地图正常"))
            self.lbl_exec.configure(foreground="#27ae60")

    def _pick_mode(self):
        """用户手动选了策略：记下来，别再被「默认逃跑」覆盖。"""
        self._mode_user_set = True
        self._sync()

    def _mount_hook(self, why=""):
        """挂载战斗监听（进 state9 自动做，与「开始自动战斗」无关）。

        这里只负责：附加进程 + 抓包 + 收包解析 + 维护战斗状态。
        绝不开启自动执行——auto_ev 默认 False，所以进战斗也只观察、不代发。
        """
        if self.eng and self.eng.is_alive():
            return False
        self._sync()
        self.eng = Engine(self.cfg, self.q)
        self.eng.auto_ev.clear()        # 只监听
        self.eng.start()
        self.hook_ready = False         # 等引擎回 ("hook_state", True) 才算挂上
        self.auto_exec = False
        self.btn.configure(text="开始自动战斗", state="disabled")
        self.v_hook.set("战斗监听：挂载中…")
        self.lbl_hook.configure(foreground="#d98a2b")
        self.stop_phase = STOPPED_READY
        self._set_exec_label(STOPPED_READY, "等待开始自动战斗")
        self.v_hint.set("")
        if why:
            self._put("sys", why)
        return True

    def _set_speed(self, pid, enable, auto=False):
        """在后台线程里打/还原加速移动补丁，结果通过队列回界面。"""
        tag = "[自动] " if auto else ""

        def work():
            ok, msgs = apply_speed_patch(pid, enable)
            # 注意：队列里 log 项是三元组 ("log", kind, text)，写成嵌套二元组
            # 会让 _drain 的 item[2] 越界，并把整个 drain 循环打断（踩过）
            self.q.put(("log", "sys" if ok else "warn",
                        tag + "加速移动：" + "；".join(msgs)))
            # 失败就把勾选框弹回去，避免界面显示和真实状态不一致
            self.q.put(("speed", bool(ok) if enable else False))

        threading.Thread(target=work, daemon=True).start()

    def _on_speed(self):
        """手动勾选/取消「加速移动」。"""
        pid = self.cfg.get("pid") or 0
        if not pid:
            self._put("warn", "加速移动：还没有可用的游戏 PID")
            self.v_spd.set(False)
            return
        self._sync()
        self._set_speed(pid, self.v_spd.get())

    def _check_speed(self):
        """只读核对加速补丁到底打没打上（给用户一个可验证的证据）。"""
        pid = self.cfg.get("pid") or 0
        if not pid:
            self._put("warn", "检查补丁：还没有可用的游戏 PID")
            return

        def work():
            try:
                if ae._is_stw_child(pid):
                    self.q.put(("log", "warn", "检查补丁：该 PID 是 STW 的子进程"))
                    return
            except Exception:
                pass
            n, lines = speed_state(pid)
            if n is None:
                self.q.put(("log", "warn", "检查补丁：" + "；".join(lines)))
                return
            total = n["p"] + n["o"] + n["x"]
            head = (f"检查补丁 PID={pid}：已打 {n['p']}/{total}，"
                    f"原始 {n['o']}，其它 {n['x']}")
            self.q.put(("log", "sys", head))
            for ln in lines:
                self.q.put(("log", "dim", "  " + ln))

        threading.Thread(target=work, daemon=True).start()

    def _auto_speed(self, pid):
        """state=9 就绪时自动开一次加速移动（同一个 PID 只做一次）。"""
        if getattr(self, "_spd_pid", 0) == pid:
            return
        self._spd_pid = pid
        self.v_spd.set(True)
        self.cfg["speed"] = True
        self._set_speed(pid, True, auto=True)

    def _toggle(self):
        """只切换「自动执行」，不再负责挂载监听 / 停引擎（文档 §5、§9、§10）。

        开始：battle_auto_active=True
              —— 不重新 Hook、不清 BC/BA/战斗状态，只打开代发权限
        停止：battle_auto_active=False
              —— 不断 Hook、不 reset socket、不退出 state9，监听继续在线
        """
        eng = self.eng
        if eng is None or not eng.is_alive():
            if not self.ready:
                self.v_hint.set("还没进游戏（state9），挂载不了战斗监听")
                return
            self._mount_hook("监听未挂载，先补挂一次")
            eng = self.eng
            if eng is None:
                return
        MODE_TXT = {"attack": "攻击", "flee": "逃跑", "catch": "抓宠"}
        if eng.auto_ev.is_set():
            eng.auto_ev.clear()
            self.auto_exec = False
            self.btn.configure(text="开始自动战斗")
            self.v_exec.set("自动执行：关（监听仍在继续）")
            self.lbl_exec.configure(foreground="#95a5a6")
            self.v_hint.set("已停止自动战斗 —— 监听保持在线")
            self._put("sys", "■ 已停止自动战斗：不再代发任何战斗指令，"
                             "战斗监听仍然在线（继续收包/更新状态）\n"
                             "   接下来会等当前战斗自然结束 → 等地图/NPC 刷新 → "
                             "稳定停止（底部状态栏可见进度）")
            self.q.put(("auto_state", False))
        else:
            eng.auto_ev.set()
            self.auto_exec = True
            self.btn.configure(text="停止自动战斗")
            self.v_exec.set("自动执行：开 · "
                            + MODE_TXT.get(self.cfg.get("mode", "flee"), "?"))
            self.lbl_exec.configure(foreground="#27ae60")
            self.v_hint.set("")
            self._put("sys", "▶ 已开启自动战斗：策略="
                             + MODE_TXT.get(self.cfg.get("mode", "flee"), "?")
                             + "（不重新挂载监听，沿用当前战斗状态）")
            self.q.put(("auto_state", True))

    def _clear(self):
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.configure(state="disabled")

    def _put(self, kind, text):
        ts = time.strftime("%H:%M:%S")
        self.txt.configure(state="normal")
        self.txt.insert("end", f"[{ts}] ", "dim")
        self.txt.insert("end", text + "\n", kind)
        self.txt.see("end")
        self.txt.configure(state="disabled")
        try:
            with open(CONSOLE_LOG, "a", encoding="utf-8") as f:
                f.write(f"[{ts}] [{kind}] {text}\n")
        except Exception:
            pass

    def _drain(self):
        """队列 -> 界面。单条消息出错只记日志，绝不能打断循环。"""
        try:
            while True:
                item = self.q.get_nowait()
                try:
                    self._drain_item(item)
                except Exception:
                    # 一条坏消息曾经把 after() 续排打断，界面从此不再刷新；
                    # 所以这里必须就地吞掉并记日志，保证循环继续。
                    hb("UI处理异常")
                    try:
                        with open(CONSOLE_LOG, "a", encoding="utf-8") as f:
                            f.write("[界面回调]\n" + traceback.format_exc())
                    except Exception:
                        pass
        except queue.Empty:
            pass
        finally:
            # 心跳：证明控制台还活着（不是卡死也不是被回收了）
            self._tick = getattr(self, "_tick", 0) + 1
            if self._tick % 25 == 0:
                self.v_alive.set("● 控制台运行中" if (self._tick // 25) % 2
                                 else "○ 控制台运行中")
            self.after(120, self._drain)

    def _drain_item(self, item):
        """处理一条队列消息。字段缺失要容错，见 _drain 的说明。"""
        kind = item[0]
        hb("UI处理:" + kind)
        if kind == "log":
            # 约定是三元组 ("log", kind, text)；写错成嵌套二元组会越界
            self._put(item[1], item[2] if len(item) > 2 else str(item[1]))
        elif kind == "battle_units":
            units, player = item[1]
            enemy_rows, ally_rows = units_to_slots(units, player)
            self.board.set_units(enemy_rows, ally_rows)
            # 「敌方空位从 [15] 排」是协议/调试知识，按文档 §8.2 不再常驻 UI
            self.v_round.set(f"参战：我方 {len(ally_rows)} / "
                             f"敌方 {len(enemy_rows)}")
        elif kind == "catch_match":
            rows = item[1]
            if not rows:
                self.v_match.set("当前战斗匹配：（本场没有存活敌方）")
            else:
                parts = []
                for r in rows:
                    mark = "✓ 命中 → 抓" if r["matched"] else "✗ 跳过"
                    parts.append(f"[0x{r['slot']:X}] {r['name']} "
                                 f"Lv{r['level']} {r['hp']}/{r['max_hp']} "
                                 f"{mark}：{r['reason']}")
                self.v_match.set("当前战斗匹配：" + " ｜ ".join(parts))
        elif kind == "catch_stat":
            d = item[1]
            # 四项固定显示（「已丢弃 0」也要显示，保证位置稳定）；
            # attempts / successes / unknown 不再上界面，但内部语义不变。
            # 文案精简（UI 瘦身文档 §6.5），字段语义不变：
            # hpmax_matched / poison_confirmed / no_match / dropped
            self.v_cstat.set(
                f"统计：HP命中 {d.get('hpmax_matched', 0)} / "
                f"毒确认 {d.get('poison_confirmed', 0)} / "
                f"未命中 {d.get('no_match', 0)} / "
                f"丢弃 {d.get('dropped', 0)}")
        elif kind == "hook_state":
            # 监听挂载状态：与「是否自动执行」完全无关
            on = bool(item[1])
            self.hook_ready = on
            if on:
                self.v_hook.set("战斗监听：已挂载（只收包，不代发）")
                self.lbl_hook.configure(foreground="#27ae60")
                self.btn.configure(
                    text="停止自动战斗" if self.auto_exec else "开始自动战斗",
                    state="normal")
            else:
                self.v_hook.set("战斗监听：未挂载")
                self.lbl_hook.configure(foreground="#95a5a6")
                self.btn.configure(state="disabled")
        elif kind == "auto_state":
            # 自动执行开关：开=代发战斗指令，关=只监听
            on = bool(item[1])
            self.auto_exec = on
            if on:
                self._set_exec_label(STOP_RUNNING)
                self.btn.configure(text="停止自动战斗",
                                   state="normal" if self.hook_ready
                                   else "disabled")
            else:
                # 具体进度交给 stop_phase 刷新；这里只先给个"正在停"的兜底文案
                self.v_exec.set("自动执行：关 · 停止流程进行中…")
                self.lbl_exec.configure(foreground="#d98a2b")
                self.btn.configure(text="开始自动战斗",
                                   state="normal" if self.hook_ready
                                   else "disabled")
        elif kind == "pet_panel":
            self.pets.update_pet_list(item[1])
        elif kind == "map_objects":
            # fid=41：地图对象 / NPC 列表（停止后用来确认地图确实刷新了）
            n, prev = item[1]
            self.v_npc.set(f"地图/NPC：{n} 个"
                           + (f"（{prev}{'…' if n > 6 else ''}）" if prev else ""))
        elif kind == "stop_phase":
            # 停止流程：RUNNING / STOP_PENDING / MAP_SYNC_WAIT / STOPPED_READY
            phase, note = item[1]
            self.stop_phase = phase
            self._set_exec_label(phase, note)
        elif kind == "phase":
            self.v_phase.set(item[1])
        elif kind == "account":
            acc, accs = item[1]
            self.cb_acct.configure(values=accs, state="readonly")
            self.v_acct.set(acc)
            self.cfg["accounts"] = accs
            self._sync()
        elif kind == "state":
            pid, s = item[1]
            self.cfg["pid"] = pid
            self.v_state.set(f"state={s['state']} "
                             f"{STATE_TXT.get(s['state'], '')}")
            self.v_pos.set(f"地图 {s['map']}  坐标 ({s['x']},{s['y']})")
        elif kind == "ready":
            d = item[1]
            self.cfg.update(pid=d["pid"], account=d["account"])
            self.ready = True
            self._was_ready = True
            self._set_enabled(True)
            self.v_phase.set(f"✔ 已进游戏（账号 {d['account']}）— "
                             "正在挂载战斗监听…")
            self._put("sys", f"游戏就绪 PID={d['pid']} 账号 {d['account']}")
            # 默认策略：逃跑（文档 §4）——用户没手动选过才强制，选过就尊重他
            if not self._mode_user_set:
                self.v_mode.set("catch")
                self._sync()
                self._put("dim", "默认策略：抓宠（点「开始自动战斗」后可随时切换）")
            # state=9 就自动开启加速移动（move+ui 21 个补丁）。
            # 这不是开启自动战斗：遇敌走位 / 战斗指令仍然要手动点「开始自动战斗」
            if self.v_auto.get():
                self._auto_speed(d["pid"])
            # 进入 state9 自动挂载战斗监听（只收包，不代发任何指令）
            self._mount_hook("state=9 已就绪 → 自动挂载战斗监听")
        elif kind == "speed":
            self.v_spd.set(bool(item[1]))
            self.cfg["speed"] = bool(item[1])
            if self.ready:
                acc = self.cfg.get("account", "")
                self.v_phase.set(
                    f"✔ 已进游戏（账号 {acc}）— 加速移动已开启"
                    if item[1] else
                    f"✔ 已进游戏（账号 {acc}）— 可以开始了")
        elif kind == "dead":
            self.ready = False
            self._spd_pid = 0
            self.v_spd.set(False)
            # 游戏没了，监听线程也要收掉，否则下次进游戏 _mount_hook 会被
            # 「引擎还活着」挡住，新 PID 永远挂不上监听
            if self.eng and self.eng.is_alive():
                self.eng.stop_flag.set()
            self.hook_ready = False
            self.auto_exec = False
            self.v_hook.set("战斗监听：未挂载")
            self.lbl_hook.configure(foreground="#95a5a6")
            self.stop_phase = STOPPED_READY
            self._set_exec_label(STOPPED_READY, "游戏已退出")
            self.pets.update_pet_list([None] * len(PET_SLOTS))
            self._set_enabled(False)
            self.btn_launch.configure(state="normal")
            self.v_phase.set("游戏未运行 — 请重新启动")
            # 只有"曾经连上过"才自动退出；否则开屏没游戏就自杀了
            if self.v_close.get() and self._was_ready:
                self._auto_close()
        elif kind == "stat":
            self.v_cnt.set(f"战斗 {item[1].get('battles', 0)} / "
                           f"遇敌包 {item[1].get('walks', 0)} / "
                           f"fid=14 {item[1].get('sent14', 0)} / "
                           f"fid=43 {item[1].get('h43', 0)}")
        elif kind == "fatal":
            self._put("warn", "!! " + item[1])
            self.hook_ready = False
            self.auto_exec = False
            self.v_hook.set("战斗监听：未挂载（引擎异常退出）")
            self.lbl_hook.configure(foreground="#c0392b")
            self.stop_phase = STOPPED_READY
            self._set_exec_label(STOPPED_READY, "引擎异常")
            self.btn.configure(text="开始自动战斗",
                               state="normal" if self.ready else "disabled")
            self.v_hint.set("")
        elif kind == "done":
            d = item[1]
            self._put("sys", f"—— 结束：{d['battles']} 场 / {d['walks']} 个遇敌包 / "
                             f"fid=14 {d['sent14']} / fid=43 "
                             f"{d['fid_in'].get('43', 0)} ——")
            self.hook_ready = False
            self.auto_exec = False
            self.v_hook.set("战斗监听：未挂载")
            self.lbl_hook.configure(foreground="#95a5a6")
            self.stop_phase = STOPPED_READY
            self._set_exec_label(STOPPED_READY, "引擎已结束")
            self.btn.configure(text="开始自动战斗",
                               state="normal" if self.ready else "disabled")
            self.v_hint.set("")


def _excepthook(exc, val, tb):
    try:
        with open(CONSOLE_LOG, "a", encoding="utf-8") as f:
            f.write("[未捕获异常]\n" + "".join(
                traceback.format_exception(exc, val, tb)))
    except Exception:
        pass
    sys.__excepthook__(exc, val, tb)


def supervisor_script():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "_sa_supervisor.py")


def _supervisor_alive(pid):
    try:
        return bool(pid) and psutil.pid_exists(pid)
    except Exception:
        return False


def ensure_supervisor(launch_new=False):
    """保证常驻 supervisor 在跑。控制台自身不持有游戏进程。

    launch_new=True 时要求 supervisor 真正拉起一个新游戏实例；
    否则只是连接已有客户端（或沿用 supervisor 已发现的）。

    返回一个 bool：True=已在运行/已拉起。
    """
    try:
        base = os.path.dirname(os.path.abspath(__file__))
        pidfile = os.path.join(base, "_sa_supervisor.pid")
        old = 0
        if os.path.exists(pidfile):
            try:
                old = int(open(pidfile, encoding="ascii").read().strip() or 0)
            except Exception:
                old = 0
        if _supervisor_alive(old):
            return True
        # 旧的 quit 指令会立刻把新起的 supervisor 停掉，先清掉
        try:
            cmdfile = os.path.join(base, "sa_supervisor_cmd.txt")
            if os.path.exists(cmdfile):
                os.remove(cmdfile)
        except Exception:
            pass
        args = [sys.executable, supervisor_script()]
        if launch_new:
            args.append("--launch")
        p = subprocess.Popen(
            args,
            cwd=base,
            creationflags=(0x00000008 | 0x01000000 | 0x08000000),  # DETACHED|BREAKAWAY|NO_WINDOW
            stdout=open(os.path.join(base, "_sa_supervisor_out.txt"), "ab"),
            stderr=subprocess.STDOUT)
        try:
            with open(pidfile, "w", encoding="ascii") as f:
                f.write(str(p.pid))
        except Exception:
            pass
        return True
    except Exception:
        return False


def start_guardian():
    """（已停用）独立守护进程。

    停用原因：它本身是一个 python.exe，会额外弹出黑框（即便带 NO_WINDOW，
    在部分启动路径下仍会瞬间出现），而闪退根因已经查清并修复（残留 supervisor
    --launch 反复拉进程 + UI 重入双开），不再需要它做现场取证。
    保留函数占位，避免旧调用报错。
    """
    return


if __name__ == "__main__":
    sys.excepthook = _excepthook
    start_guardian()
    # 黑匣子：faulthandler 抓段错误级别的硬崩（ctypes/frida 这类不会抛 Python
    # 异常的崩溃），落盘到 stw_crash.txt；心跳线程每秒写 stw_heartbeat.txt。
    try:
        _crash_fh = open(CRASH_LOG, "a", encoding="utf-8", buffering=1)
        _crash_fh.write(f"\n==== {time.strftime('%F %T')} 控制台启动 "
                        f"pid={os.getpid()} ====\n")
        faulthandler.enable(file=_crash_fh, all_threads=True)
    except Exception:
        pass
    threading.Thread(target=hb_thread, daemon=True).start()
    install_exit_probe()
    try:
        app = App()
    except Exception as e:
        try:
            with open(CONSOLE_LOG, "a", encoding="utf-8") as f:
                f.write("[构造失败]\n" + traceback.format_exc())
        except Exception:
            pass
        messagebox.showerror("启动失败", f"{e}\n\n详见 {CONSOLE_LOG}")
        raise
    if "--smoke" in sys.argv:          # 冒烟：界面建起来就退出，验证构造路径
        app.after(2500, app.destroy)
    # mainloop 就算炸了也不让控制台消失，问用户要不要再来一轮
    while True:
        try:
            app.mainloop()
            break
        except Exception as e:
            with open(CONSOLE_LOG, "a", encoding="utf-8") as f:
                f.write("[mainloop 异常]\n" + traceback.format_exc())
            if not messagebox.askretrycancel(
                    "控制台异常",
                    f"{type(e).__name__}: {e}\n\n控制台可以继续跑，要继续吗？"):
                break
