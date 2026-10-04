"""丢弃宠物 端到端测试 —— 对应《丢弃宠物.MD》

不连游戏：把真实的 Engine 跑起来，frida / 网桥 / 内存快照换成假的，
然后喂一整场「抓宠」的真实报文进去，看它到底什么时候发 fid=21、发什么。

    Case 1  抓到非满档 -> 脱离战斗后发 C>S fid=21，内容为 x|y|slot|x+y+slot
    Case 2  抓到满档   -> 一个 fid=21 都不发
    Case 3  发出后不本地清空：栏位只认随后到来的 S>C fid=46（Kx|0|）
    Case 4  关掉「丢弃不满档」开关 -> 不发
    Case 5  空槽 / 只有短包（判不了满档）-> 不发

硬约束（文档 §1 / §2 / §4）：
    · 只丢有宠的槽
    · 组 L2 再走现有 L1 编码器，不带名字 / pet_id / uid
    · 不本地预清空，以 fid=46 为准
    · 只更新报文里出现的槽
"""
import os
import queue
import sys
import tempfile
import time

# 仓库根 + stw_ui 包目录进 sys.path（从 __file__ 推，不写死绝对路径）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "stw_ui"))
sys.path.insert(0, _ROOT)
from stw_ui import stw_ui                                  # noqa: E402
import stw_engine                                 # noqa: E402
import fast_encounter as fe                      # noqa: E402
from stw_engine import Engine                           # noqa: E402
from stw_pet import (CATCH_SAMPLE_TEXT, build_drop_l2,  # noqa: E402
                     parse_catch_rule_text)
from stw_pet import grow_stats                    # noqa: E402

sa = stw_engine.sa
stw_engine.LOG = os.path.join(tempfile.gettempdir(), "_test_drop_log.jsonl")

ACCOUNT = "testacct"
KEY = sa.make_l2_key(ACCOUNT)

RULES = {r["name"]: r for r in
         [parse_catch_rule_text(CATCH_SAMPLE_TEXT)]}
assert "巴朵兰恩" in RULES, sorted(RULES)
# 规则命中条件：巴朵兰恩 Lv100 maxHP=913（与 _test_catch.py 同一条）
assert 913 in RULES["巴朵兰恩"]["levels"][100]["max_hp"]

# 敌方 F = 巴朵兰恩 Lv0x64=100 hp/maxhp=0x391=913
BC_ALIVE = ("BC|0|0|UV2D||18AD7|8C|4E1|5A9|5|1|巴朵兰恩|8C|40E|55A|"
            "5|min-1||187B2|80|41F|4E3|1|0||0|0|0|"
            "F|巴朵兰恩||18809|64|391|391|1|0||0|0|0|")
BC_DEAD = ("BC|0|0|UV2D||18AD7|8C|4E1|5A9|5|1|巴朵兰恩|8C|40E|55A|"
           "5|min-1||187B2|80|41F|4E3|1|0||0|0|0|"
           "F|巴朵兰恩||18809|64|0|391|1|0||0|0|0|")

# 抓到的宠（长包，Lv1，非满档）
K0_BAD = ("K0|1|100373|100|100|0|0|16984|-1|1|5|4|3|100|"
          "0|0|0|0|7|1|巴朵兰恩||")


def full_pet_k(slot, level, adds):
    """正向造一只「源码确实能生成出来」的满档巴朵兰恩（长包）。"""
    # 走 stw_pet.grow_stats，别在测试里另抄一份公式（口径一分叉就自洽了）
    V, S, T, D = 25 + adds[0], 39 + adds[1], 22 + adds[2], 27 + adds[3]
    hp, atk, df, agi = grow_stats(level, V, S, T, D)
    return ("%s|1|100373|%d|%d|0|0|16984|-1|%d|%d|%d|%d|100|"
            "0|0|0|0|7|1|巴朵兰恩||" % (slot, hp, hp, level, atk, df, agi))


# ⚠ 等级不能取 1：K=(1-1)*4+27=27 太小，面板数值会大量撞车，
#   严格判定（要求「不存在非满档方案也能得到同一面板」）必然 False。
K0_GOOD = full_pet_k("K0", 20, (2, 3, 2, 3))


class FakeApi:
    def __init__(self):
        self.q = []

    def dump(self):
        out, self.q = self.q, []
        return out


class FakeBridge:
    def __init__(self):
        self.sent = []

    def send(self, b):
        self.sent.append(b)

    def status(self):
        return {"ready": True, "socket": 1}

    def close(self):
        pass


class FakeGame:
    """角色站在 (68,35)：文档实包 丢 K0 @ (68,35) -> 68|35|0|103"""

    def snapshot(self):
        return {"state": 9, "x": 68, "y": 35, "map": 999999}

    def close(self):
        pass


def fake_setup(self):
    self.pid = 0
    self.key = KEY
    self.api = FakeApi()
    self.b = FakeBridge()
    self.g = FakeGame()
    self.sess = self.sn = self.snc = self.hook_sc = None


Engine.setup = fake_setup
Engine.set_hook = lambda self, on: None


def frame(fid, payload):
    msg = b"&;" + str(fid).encode() + b";" + sa.enstring(payload, KEY) + b";#;"
    return {"hex": stw_engine.enc(msg).hex(), "dir": "IN"}


def decode_out(raw):
    """解一条出站的真报文 -> (fid, [字段...])"""
    p = sa.decode_layer1(raw).split(b";")
    return p[1].decode(), [sa.deint(x, KEY) for x in p[2:-2]]


def sent21(e):
    out = []
    for b in e.b.sent:
        try:
            fid, vals = decode_out(b)
        except Exception:
            continue
        if fid == "21":
            out.append(vals)
    return out


def wait_until(pred, timeout=10.0, what=""):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if pred():
            return True
        time.sleep(0.05)
    raise AssertionError(f"等不到条件成立：{what}（{timeout}s）")


def stop(e):
    e.stop_flag.set()
    e.join(timeout=5)


def start_engine(drop=True):
    q = queue.Queue()
    cfg = {"pid": 0, "account": ACCOUNT, "accounts": [ACCOUNT],
           "fast_enc": False, "fast_battle": True, "mode": "catch",
           "interval": 0.1, "secs": 100000.0, "maxb": 999,
           "show46": False, "showraw": False,
           "catch": {"rules": RULES, "no_match_action": "flee",
                     "pet_action": "attack", "after_success": "continue",
                     "stop_count": 1, "drop_non_full": drop}}
    e = Engine(cfg, q)
    e.auto_ev.set()          # 抓宠要真的代发
    e.start()
    wait_until(lambda: e.battle_hook_active, what="引擎挂载监听")
    return e, q


def play_catch(e, k_packet):
    """打完一整场：遇敌 -> BC -> 抓 -> BT -> K -> 目标离场 -> 胜利收尾。"""
    e.api.q.extend([
        frame(7, "7|1|"),
        frame(15, BC_ALIVE),
        frame(15, "BA|18000|1|"),        # 操作窗口 -> 发 T|F + W|1|F
    ])
    wait_until(lambda: any(decode_out(b)[0] == "14" for b in e.b.sent),
               what="代发抓宠指令")
    e.api.q.extend([
        frame(15, "BT|a0|rF|f1|"),       # BT 结算
        frame(46, k_packet),             # 新槽出现
        frame(15, BC_DEAD),              # 目标已离场
        frame(15, "BA|18000|2|"),        # 最终 BA -> 敌方全灭 -> finish
    ])


def play_catch_late(e, packets):
    """先打完战斗，K 包**晚于**战斗结束才到（时序修正 Case B/C/D/E）。

    packets: 战斗结束后才喂进来的 fid=46 列表（可含短包+长包）。
    """
    e.api.q.extend([
        frame(7, "7|1|"),
        frame(15, BC_ALIVE),
        frame(15, "BA|18000|1|"),        # 操作窗口 -> 发 T|F + W|1|F
    ])
    wait_until(lambda: any(decode_out(b)[0] == "14" for b in e.b.sent),
               what="代发抓宠指令")
    e.api.q.extend([
        frame(15, "BT|a0|rF|f1|"),       # BT 结算
        frame(15, BC_DEAD),              # 目标已离场
        frame(15, "BA|18000|2|"),        # 最终 BA -> 敌方全灭 -> finish
    ])
    wait_until(lambda: e.catch_stats["successes"] >= 1
               or e.catch_stats["unknown"] >= 1,
               what="战斗结果结算（此时 K 长包还没到）")
    # 战斗已彻底结束，角色已回地图 —— 现在才来 K 包
    for pk in packets:
        e.api.q.append(frame(46, pk))


print("=" * 70)
print("丢弃宠物（fid=21）端到端测试")
print("=" * 70)

# ---------------------------------------------------------------------------
# Case 1：抓到非满档 -> 脱离战斗后发 fid=21
# ---------------------------------------------------------------------------
print("\n--- Case 1：抓到非满档宠 ---")
e, q = start_engine(drop=True)
play_catch(e, K0_BAD)
wait_until(lambda: e.catch_stats["successes"] == 1, what="捕捉成功结算")
wait_until(lambda: sent21(e), what="发出 fid=21")
got = sent21(e)
print(f"   已发 fid=21：{got}")
assert got == [[68, 35, 0, 103]], got
assert build_drop_l2(68, 35, "K0") == "68|35|0|103"
assert e.catch_stats["dropped"] == 1
# 发出之后、fid=46 回来之前，本地不许清空
assert e.pet_panel.get("K0") is not None, "发完不许本地预清空"
print("OK 抓到非满档 -> fid=21 [68,35,0,103]（= 文档实包 68|35|0|103）")

# ---- 服务端回 K0|0| -> 面板清空 ----
e.api.q.append(frame(46, "K0|0|"))
wait_until(lambda: e.pet_panel.get("K0") is None, what="K0|0| 清空面板")
assert sent21(e) == got, "fid=46 不该再触发丢弃"
print("OK 收到 K0|0| 后面板 K0 = 「空」，且不会重复丢弃")
e.stop_flag.set()
e.join(timeout=5)

# ---------------------------------------------------------------------------
# Case 2：抓到满档 -> 一个 fid=21 都不发
# ---------------------------------------------------------------------------
print("\n--- Case 2：抓到满档宠 ---")
e, q = start_engine(drop=True)
play_catch(e, K0_GOOD)
wait_until(lambda: e.catch_stats["successes"] == 1, what="捕捉成功结算")
time.sleep(1.5)
assert e.pet_panel["K0"]["full"] is True, e.pet_panel["K0"]
assert sent21(e) == [], f"满档宠绝不能丢：{sent21(e)}"
assert e.catch_stats["dropped"] == 0
print("OK 满档宠一个 fid=21 都不发（★满档保留在宠物栏）")
e.stop_flag.set()
e.join(timeout=5)

# ---------------------------------------------------------------------------
# Case 3：关掉开关 -> 不发
# ---------------------------------------------------------------------------
print("\n--- Case 3：关掉「丢弃不满档」开关 ---")
e, q = start_engine(drop=False)
play_catch(e, K0_BAD)
wait_until(lambda: e.catch_stats["successes"] == 1, what="捕捉成功结算")
time.sleep(1.5)
assert sent21(e) == [], sent21(e)
assert e.pet_panel.get("K0") is not None, "不丢就得留着"
print("OK 开关关闭：非满档宠也保留，不发 fid=21")
e.stop_flag.set()
e.join(timeout=5)

# ---------------------------------------------------------------------------
# Case 4：只收到短包（判不了满档）-> 不发；空槽 -> 不发
# ---------------------------------------------------------------------------
print("\n--- Case 4：判不了满档 / 空槽 一律不发 ---")
e, q = start_engine(drop=True)
# 短包里没有等级，拿不到确定结论
e._update_pet("K3|xZa|1256|0|18153|327|215|190|100|0|20|80|0|",
              new_catch=True)
assert e.pet_panel["K3"]["partial"] is True
assert e._enqueue_drop("K3", e.pet_panel["K3"]) is False
# 空槽
assert e._enqueue_drop("K2", None) is False
e.drop_queue.append("K4")            # 槽里其实没宠
assert e._flush_drops() == 0
assert sent21(e) == [], sent21(e)
print("OK 短包（无等级）与空槽都不发 fid=21，宁可留着也不误丢")
e.stop_flag.set()
e.join(timeout=5)

# ===========================================================================
# 时序回归：完整长包晚于战斗结束 / 短包先到长包后到（修正方案 §11）
# ===========================================================================
K3_BAD = K0_BAD.replace("K0|", "K3|", 1)          # 非满档，换到 K3
K3_GOOD = K0_GOOD.replace("K0|", "K3|", 1)        # 满档，换到 K3
K3_SHORT = "K3|xZa|1256|0|18153|327|215|190|100|0|20|80|0|"

print("\n" + "=" * 70)
print("时序回归（K 完整长包晚于战斗结束 / 短包先到）")
print("=" * 70)

# ---- Case A：现有正常顺序，行为不变 ----
print("\n--- Case A：正常顺序 BT->K长包->BE（非满档）---")
e, q = start_engine(drop=True)
play_catch(e, K0_BAD)
wait_until(lambda: sent21(e), what="发出 fid=21")
assert sent21(e) == [[68, 35, 0, 103]], sent21(e)
assert e.pet_panel["K0"]["full"] is False
assert e.catch_stats["dropped"] == 1
print("OK Case A：正常顺序仍按原样完成 判定+丢弃")
stop(e)

# ---- Case B：完整 K 晚于战斗结束（本次实战的根因场景）----
print("\n--- Case B：BT -> 最终BA(finish) -> K长包（晚到）---")
e, q = start_engine(drop=True)
play_catch_late(e, [K3_BAD])
wait_until(lambda: e.pet_panel.get("K3") is not None, what="晚到 K3 进宠物栏")
# 关键：晚到的长包必须仍被认作新抓宠 -> 跑到决策完成
wait_until(lambda: sent21(e), what="晚到长包触发 fid=21")
assert sent21(e) == [[68, 35, 3, 106]], sent21(e)
assert e.pet_panel["K3"]["full"] is False, e.pet_panel["K3"]
assert e.catch_stats["dropped"] == 1
assert e.pet_panel.get("K3") is not None, "发完不许本地预清空"
print("OK Case B：晚于战斗结束的长包仍能识别新抓宠 → fid=21 [68,35,3,106]")
# 服务端回 K3|0| 才清空
e.api.q.append(frame(46, "K3|0|"))
wait_until(lambda: e.pet_panel.get("K3") is None, what="K3|0| 清空")
print("OK Case B：收到 K3|0| 后面板才清空")
stop(e)

# ---- Case C：短包先到 -> 战斗结束 -> 长包后到 ----
print("\n--- Case C：BT -> K短包 -> 最终BA(finish) -> K长包 ---")
e, q = start_engine(drop=True)
play_catch_late(e, [K3_SHORT])
wait_until(lambda: e.pet_panel.get("K3") is not None, what="短包先进栏")
# 短包阶段：不判满档、不丢弃
time.sleep(0.8)
assert sent21(e) == [], f"短包阶段不许丢：{sent21(e)}"
assert e._pend is not None and e._pend["cand"] == "K3", \
    "短包必须记住候选槽 K3（等长包）"
print("OK Case C：短包阶段不判满档、不丢弃，已记住候选槽 K3")
# 长包到达 -> 补做判定
e.api.q.append(frame(46, K3_BAD))
wait_until(lambda: sent21(e), what="长包补做判定后发出 fid=21")
assert sent21(e) == [[68, 35, 3, 106]], sent21(e)
assert e.pet_panel["K3"]["full"] is False
print("OK Case C：长包到达后补做满档判断并入丢弃队列")
stop(e)

# ---- Case D：晚到的是满档宠 -> ★满档，不丢 ----
print("\n--- Case D：晚到的是满档宠 ---")
e, q = start_engine(drop=True)
play_catch_late(e, [K3_GOOD])
wait_until(lambda: e.pet_panel.get("K3", {}) and
           e.pet_panel["K3"].get("full") is True, what="晚到满档宠标记")
time.sleep(1.2)
assert sent21(e) == [], f"满档宠绝不能丢：{sent21(e)}"
assert e.drop_queue == [], e.drop_queue
assert e.pet_panel["K3"]["full"] is True
print("OK Case D：晚到满档宠显示 ★满档，drop_queue 为空，不发 fid=21")
stop(e)

# ---- Case E：晚到非满档 + 开关开启 -> 地图态发一次 fid=21 ----
print("\n--- Case E：晚到非满档 + 开关开启 ---")
e, q = start_engine(drop=True)
play_catch_late(e, [K3_BAD])
wait_until(lambda: sent21(e), what="地图态发出 fid=21")
assert sent21(e) == [[68, 35, 3, 106]], sent21(e)
assert e.catch_stats["dropped"] == 1
assert e.pet_panel.get("K3") is not None, "不等 Kx|0| 就清空 = 违规"
e.api.q.append(frame(46, "K3|0|"))
wait_until(lambda: e.pet_panel.get("K3") is None, what="Kx|0| 才清空")
print("OK Case E：地图态发一次 fid=21，收到 Kx|0| 才清空宠物栏")
stop(e)

# ---- Case F：已有槽只有短包 -> 不能被误认成新槽 ----
print("\n--- Case F：抓宠前某槽已有宠但只有短包 ---")
e, q = start_engine(drop=True)
# K2 抓宠前就"有宠"，但只有过短包（名字从未同步）
e._update_pet("K2|xZa|900|0|111|10|10|10|100|0|0|0|", new_catch=False)
assert e.pet_panel["K2"] is not None
e.open_pend("巴朵兰恩")
pend = e._pend
assert "K2" in pend["before"], (
    "只有短包的已有宠必须算进「抓宠前已占用槽」，"
    f"实际 before={pend['before']}")
ok, why = e.match_pend_slot("K2", None, "巴朵兰恩")
assert ok is False, f"已有短包槽不能被认成新宠：{why}"
assert "抓宠前已占用" in why, why
print(f"OK Case F：已有短包槽计入 before={sorted(pend['before'])}，不误认成新宠")
stop(e)

# ---- Case G：已有同名旧宠刷新 -> 不触发 ----
print("\n--- Case G：宠物栏里已有同名「巴朵兰恩」在刷新 ---")
e, q = start_engine(drop=True)
e.k_names["K1"] = "巴朵兰恩"          # 抓宠前 K1 就有一只同名旧宠
e._update_pet(K0_BAD.replace("K0|", "K1|", 1), new_catch=False)
assert e.pet_panel["K1"] is not None
e.open_pend("巴朵兰恩")
assert "K1" in e._pend["before"]
ok, why = e.match_pend_slot("K1", None, "巴朵兰恩")
assert ok is False and "抓宠前已占用" in why, why
# 满档不能被旧宠刷新触发
assert e.pet_panel["K1"]["full"] is False
assert sent21(e) == [], sent21(e)
assert e.drop_queue == []
print("OK Case G：同名旧宠刷新不认作新宠，不判满档、不丢弃")
stop(e)

# ---- Case H：关闭自动丢弃 -> 保留 ----
print("\n--- Case H：晚到非满档 + 关闭自动丢弃 ---")
e, q = start_engine(drop=False)
play_catch_late(e, [K3_BAD])
wait_until(lambda: e.pet_panel.get("K3") is not None, what="晚到 K3 进栏")
time.sleep(1.2)
assert sent21(e) == [], sent21(e)
assert e.drop_queue == [], e.drop_queue
# 宠物信息仍要正常显示
assert e.pet_panel["K3"]["level"] == 1, e.pet_panel["K3"]
print("OK Case H：开关关闭时仍完成判定并显示宠物信息，不入队列、不发 fid=21")
stop(e)

# ---- 附加：同一只宠多次 K 刷新，决策只执行一次 ----
print("\n--- 附加：同一新宠反复刷新，决策只做一次 ---")
e, q = start_engine(drop=True)
play_catch_late(e, [K3_BAD])
wait_until(lambda: sent21(e), what="首次丢弃")
n_before = len(sent21(e))
for _ in range(3):
    e.api.q.append(frame(46, K3_BAD))
time.sleep(1.2)
assert len(sent21(e)) == n_before, f"重复刷新不该重复丢弃：{sent21(e)}"
assert e.drop_queue == [], e.drop_queue
print(f"OK 同一宠 4 次 K 刷新 → 只发 {n_before} 次 fid=21")
stop(e)

# ---------------------------------------------------------------------------
# Case 5：界面开关 —— 「抓到非满档就丢弃」写进 cfg["catch"]
# ---------------------------------------------------------------------------
print("\n--- Case 5：界面开关 ---")
import tkinter as tk                                # noqa: E402

app = stw_ui.App()
app.update()
assert hasattr(app, "v_dropnf"), "抓宠面板必须有「丢弃不满档」开关"
assert app.v_dropnf.get() is False, "默认不丢弃（保守）"
app.v_dropnf.set(True)
app._sync()
assert app.cfg["catch"]["drop_non_full"] is True, app.cfg["catch"]
app.v_dropnf.set(False)
app._sync()
assert app.cfg["catch"]["drop_non_full"] is False
print("OK 界面开关：勾选/取消 → cfg['catch']['drop_non_full'] 同步，默认关闭")
app.destroy()

print("\nRESULT: PASS")
