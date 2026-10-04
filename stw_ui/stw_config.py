"""STW 全局配置：路径、常量、阈值、状态枚举（重构 v2.0 §3.1）。

所有模块统一从这里取配置，禁止各自散落一份。
⚠ 本模块会被最早导入，所以 sys.path 注册也在这里做：
  PKG_DIR  是本包目录（stw_ui/），auto_encounter / _mapdata / _frida_agent 都在这里，
           必须进 sys.path，否则 stw_engine / stw_process 在 import 阶段就炸。
  BASE_DIR 是仓库根，catch_rules.json 等数据文件放这里。

✨ 两个目录都从 __file__ 推出来，不再写死 C:\\Users\\...，换台机器/换目录直接能跑。
"""
import os
import sys


# 本包目录 = stw_config.py 所在目录（stw_ui/）
PKG_DIR = os.path.dirname(os.path.abspath(__file__))
# 仓库根 = 包目录的上一级
BASE_DIR = os.path.dirname(PKG_DIR)
# 历史遗留：有些依赖曾被整理进 shit/ 子目录，存在就也挂上去（不存在则忽略）
SHIT_DIR = os.path.join(BASE_DIR, "shit")
for _p in (BASE_DIR, PKG_DIR, SHIT_DIR):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)


# L2 编解码模块（sa_codec）。每次升级都改版本号，所以：
#   1) 可用环境变量 SA_CODEC 覆盖；
#   2) 写死的路径不存在时，resolve_codec() 会退回「同目录挑版本号最高的」。
CODEC = os.environ.get(
    "SA_CODEC",
    r"C:\Users\ptelegion\Downloads\dumpcap_realtime_stream_v31_encounter_rescue.py")


def resolve_codec(path=None):
    """定位 sa_codec（dumpcap_realtime_stream_vNN_encounter_rescue.py）。

    这份文件每次升级都会改版本号，而 `CODEC` 是写死的绝对路径 —— 一旦改名，
    依赖它的模块在 import 阶段就 FileNotFoundError，整个控制台起不来
    （2026-10-02 v30 → v31 时挂过一次，8 个测试全红）。
    所以：写死路径不存在时，退回到「同目录里挑版本号最高的那个」。
    """
    import glob
    import re
    path = path or CODEC
    if os.path.isfile(path):
        return path
    pat = os.path.join(os.path.dirname(path),
                       "dumpcap_realtime_stream_v*_encounter_rescue.py")
    best, best_v = None, -1
    for p in glob.glob(pat):
        m = re.search(r"_v(\d+)_", os.path.basename(p))
        if m and int(m.group(1)) > best_v:
            best, best_v = p, int(m.group(1))
    if best is None:
        raise FileNotFoundError(
            f"找不到编解码模块：{path} 不存在，且同目录没有 "
            f"dumpcap_realtime_stream_v*_encounter_rescue.py")
    print(f"[warn] CODEC 指向的文件不存在（{os.path.basename(path)}），"
          f"自动改用 {os.path.basename(best)}；请同步更新 stw_config.CODEC")
    return best


GAME_EXE = r"D:\zcgd2.5(new)\sa_2903.exe"
# 工作目录必须是 D:\zcgd2.5(new)！实测用 SACH-MX0.30 或继承当前目录启动，
# 进程会立刻以 0xC0000005 (STATUS_ACCESS_VIOLATION) 崩掉。
# （STW 子进程命令行里那个 "..\sa_2903.exe" 只是 lpCommandLine 的字符串，
#   真正的应用路径由 lpApplicationName 给的全路径决定，cwd 是 D:\zcgd2.5(new)）
GAME_CWD = r"D:\zcgd2.5(new)"
# 启动参数（与 STW 拉起时完全一致，实测抄自 STW 子进程命令行）：
#   updated realbin:15 adrnbin:15 sprbin:4 spradrnbin:5 encode:108 windowmode
GAME_ARGS = ("updated realbin:15 adrnbin:15 sprbin:4 "
             "spradrnbin:5 encode:108 windowmode")
WRITE_SITE = 0x449353
RN_MAX = 128            # 真实客户端实测 rn 全在 0~100
MAX_ROUNDS = 3
MAX_BATTLE_ROUNDS = 300      # 单场最多代发多少回合（BA 驱动的硬上限）
BATTLE_TIMEOUT = 40.0       # 单场最长 40s，超时兜底收尾
# ---- 停止流程：地图/NPC 同步保护（stop_battle_map_sync_design.md）----
# 只作用于「点击停止自动战斗」，绝不干预运行中的挂机循环。
STOP_RUNNING = "RUNNING"            # 自动执行中
STOP_PENDING = "STOP_PENDING"       # 已停发动作，等当前战斗自然结束
MAP_SYNC_WAIT = "MAP_SYNC_WAIT"     # 战斗已结束，等地图/NPC 刷新
STOPPED_READY = "STOPPED_READY"     # 稳定停止：监听在线，地图正常
MAP_SYNC_FIDS = ("41", "37", "4")   # 41=地图单位/NPC 刷新 37=地图场景 4=场景切换确认
MAP_SYNC_SCORE_NEED = 2             # 凑够几个同步包就认为地图恢复
MAP_READY_DELAY = 1.5               # 再等 1.5s 让客户端完成 UI/NPC 绘制
MAP_SYNC_TIMEOUT = 10.0             # 兜底：一直收不到同步包也不能永远"等待"
# 「肯定已经离开 state9（不在世界里）」的状态集合。
# ⚠ 战斗中的 state=10 绝对不能算离开——战斗监听必须在战斗里继续在线。
OUT_OF_WORLD_STATES = (0, 1, 2, 3, 7, 11)
LOG = "stw_ui_log.jsonl"
CONSOLE_LOG = "stw_console_log.txt"   # 界面上所有输出同时落盘，方便事后查崩溃
CRASH_LOG = "stw_crash.txt"           # faulthandler：抓段错误/访问违例时的 Python 栈
HEARTBEAT = "stw_heartbeat.txt"       # 每秒一行，进程硬崩也能看出死在哪一步

STATE_TXT = {0: "启动中", 1: "登录界面", 2: "选服务器", 3: "选角色",
             7: "登出中", 9: "地图中", 10: "战斗中", 11: "断线/弹窗"}


SLOT_ROWS = 10


# ---- 战斗槽位 ----
# BC 报文结构 = 「1 个全局字段」+「每个战斗槽 13 个字段」，块首就是 slot。
# 敌我完全由 slot 判定，不需要任何血量/名字锚点（血量会掉、名字会错位，
# 只有 slot 是协议写死的）：
#     我方 0x0 ~ 0x9 ：0~4 = 角色(+骑宠复合)，5~9 = 战宠
#     敌方 0xF ~ 0x18：即十进制 15~24，共 10 个
# ⚠ 注意敌方槽位 10/11/12/13 是十六进制，不是十进制编号。
SLOT_FIELDS = 13          # 每个战斗槽的字段数
ALLY_SLOT_MAX = 0x9       # 我方槽位上限（含）
ENEMY_SLOT_MIN = 0xF      # 敌方槽位下限（含）
ENEMY_SLOT_MAX = 0x18     # 敌方槽位上限（含），超出范围的槽位一律不算敌方
# 槽位在块内的下标
I_SLOT, I_NAME, I_EXTRA = 0, 1, 2
I_UID, I_LV, I_HP, I_HPMAX = 3, 4, 5, 6
I_STATE, I_HAS_MOUNT = 7, 8
I_MNAME, I_MLV, I_MHP, I_MHPMAX = 9, 10, 11, 12


# ---- BA（行动机会）应答规则 ----
# 实测报文形如  BA|38000|3|      （第 2 段是十六进制 value，第 3 段是回合计数）
#   low = value & 0x3FF
#     low == 0      -> 服务器开出一次操作机会，可以发 1 条 fid=14
#     low == 0x3DF  -> 不发东西
#     low == 0x3FF  -> 不发东西，等服务器结算
#   其它值（实测见过 0x1 / 0x20 / 0x21，都是我们发完指令后的回执）-> 不发
#
# 抓包佐证（stw_ui_log.jsonl 一场完整战斗）：
#   BC -> BA|38000|n|      ← 回合开始，等指令（low=0）
#   [我们发 fid=14]        -> BA|38001|n| / BA|38021|n|  <- 回执（low=1/0x21）
#   BH                     <- 伤害结算
#   下一回合重复
BA_MASK = 0x3FF
BA_ACT = 0x000                 # 可操作（还没收到任何指令）
# 🔥 low 是「行动完成位图」，不是"能不能操作"的开关：
#     0x000 = 新回合的操作窗口，等客户端下指令
#     0x001 = slot0（角色）完成
#     0x020 = slot5（宠物）完成
#     0x021 = 角色 + 宠物都完成 -> 服务器结算
#     0x3DF = 0~9 中除 slot5 外都完成
#     0x3FF = 0~9 全完成
# 非零一律当作服务器 ACK 观察，不发东西（我们一次就把 H 和 W 都发了）。
BA_BIT_CHAR = 0x01
BA_BIT_PET = 0x20


CATCH_RULES_FILE = "catch_rules.json"   # 规则库持久化（set 转 list 后写 JSON）


# ---------------------------------------------------------------------------
# 上毒（猛毒）验证模型 —— 抓宠智能筛选逻辑开发文档 v2 §5 / §7
# ---------------------------------------------------------------------------
# 毒伤公式（服务端 magic.txt，动作说明文档 §5）：
#     掉血 = (K * (V+S+T+D) // 100 - 20) // 4
#     K = (等级-1)*4 + 27
#
# ★ 口径以用户实测表为准（95~105 级，逐条吻合）：
#     C:/Users/ptelegion/Downloads/巴朵兰恩_95-105_MAXHP_猛毒DeltaHP.json
#     95:118  96:120  97:121  98:122  99:123  100:125
#     101:126 102:127 103:128 104:129 105:131
#   满档原始四维和恒为 25+39+22+27+10=123，所以**每个等级只有一个值**。
#
# ⚠⚠ 别把面板数值代进这个公式（两个都踩过）：
#     · hp（HP上限）不是「体」，约为「体」的 4 倍，代进去 Δhp 偏大约 2.6 倍；
#     · 面板攻/防/敏（grow_stats，带交叉项，Lv104 真宠攻=204）也不是这里的
#       攻/防/敏 —— 毒伤公式的四项和是「原始四维和 × K%」，与面板展示口径不同，
#       用面板值会算出 145/146 这类与实测表不符的数。
#
# 可配置仍保留两种（默认 derived）：
#     "derived"：掉血 = (K * sum(V,S,T,D) // 100 - 20) // 4   ← 上表口径
#     "base"   ：掉血 = (sum(V,S,T,D) - 20) // 4，恒为 25，无区分力，仅作对照
#   验证不通过时默认只记录不排除（poison_verify="log"），
#   日志会同时打出「预期集合 vs 实际 Δhp」。
POISON_DMG_MODES = ("derived", "base")
POISON_STATE = 8      # BC 单位 state：8 = 中毒中（动作说明文档 §5.2）
POISON_VERIFY_MODES = ("off", "log", "strict")



# ---------------------------------------------------------------------------
# 抓宠配置默认值（cfg["catch"]，阈值/策略统一在这里声明）
# ---------------------------------------------------------------------------
CATCH_CFG_DEFAULTS = {
    "rules": {},
    "no_match_action": "flee",       # flee / attack / silent
    "pet_action": "attack",          # attack（已抓包）/ wait（实验）
    "after_success": "continue",     # continue / stop / count
    "stop_count": 1,
    # 默认关闭（保守）：丢宠不可逆，必须用户显式勾选才生效
    "drop_non_full": False,          # 抓到非满档就丢（丢弃宠物.MD）
    # —— 抓宠前上毒（抓宠智能筛选逻辑开发文档 v2 §3~§9）——
    # 默认关闭：会多发好几个回合，先按老流程跑通再开。
    "poison_enabled": False,
    "poison_skill": 2,               # 猛毒在技能栏第几格（本号=2）
    "poison_hp_ratio": 0.10,         # 控血阈值：HP% 低于它才抓
    "poison_verify": "log",          # off / log / strict
    "poison_dmg_mode": "derived",    # derived / base
}

