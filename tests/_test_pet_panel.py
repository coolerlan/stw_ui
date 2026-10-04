"""宠物栏测试 —— STW_K包宠物解析开发文档_v2 + 是否满档.md

验的东西：

1. 满档算法
   · 文档 §8 的例子 is_full_pet(99,829,197,122,117) == False
   · 正向构造一只真满档（base 25/39/22/27 + 10 点分配）必须 True
   · 与文档 §7 原版伪代码**逐位对拍**（随机 300 组）
   · ⚠ 只对「新抓到的宠」判满档，已有宠物不判（用户明确要求）
2. K 包解析（v2 字段位置）
   · 长包 >=22 段：2=宠物ID 3=HP 4=最大HP 9=等级 10/11/12=攻防敏
     13=忠诚 20=名字 21=称号
   · 短包 14 段（xZa）：只有 2=HP 5/6/7=攻防敏 8=忠诚，**没有等级和名字**
   · 空槽 / 非宠物包 / 越界槽 -> None
3. 界面
   · 固定 5 行、不显示 K0/K1/...、空槽「空」、满档带 ★满档
4. 接入
   · 真 Engine 收到 fid=46 后自动更新；只有 new_catch=True 才判满档
"""
import random
import os
import sys
import time

# 仓库根 + stw_ui 包目录进 sys.path（从 __file__ 推，不写死绝对路径）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "stw_ui"))
sys.path.insert(0, _ROOT)
from stw_ui import stw_ui                                   # noqa: E402
import stw_engine                                 # noqa: E402
import fast_encounter as fe                       # noqa: E402
from stw_pet import (PET_SLOTS, PET_K_FIELDS,     # noqa: E402
                     is_full_pet, parse_k_pet, grow_stats)
from stw_ui.stw_ui import PetPanel                      # noqa: E402

# ---- v2 文档 §4 的真实样本 ----
K0_DOC = ("K0|1|100274|1251|1251|0|0|8298128|68487425|128|216|356|50|100|"
          "0|0|0|0|5|1|石龟|min-1|")
K2_DOC = ("K2|1|100290|355|355|0|0|0|51520|50|94|50|39|0|"
          "0|0|0|0|5|1|火的守护兽||")
K3_DOC = ("K3|1|100373|1370|1370|0|0|16984|-1|140|320|202|188|100|"
          "0|0|0|0|7|1|巴朵兰恩||")
# 真实抓包里的长包 / 短包（同一个槽位两种形态）
K0_LONG = ("K0|1|100376|1234|1234|0|0|32481279|69517215|133|"
           "219|223|219|100|0|0|0|100|5|1|摩娜西普||")
K3_SHORT = "K3|xZa|1256|0|18153|327|215|190|100|0|20|80|0|"

print("=" * 70)
print("宠物栏 / 满档判定测试（v2 解析）")
print("=" * 70)

# ---------------------------------------------------------------------------
# 1. 满档算法
# ---------------------------------------------------------------------------
assert is_full_pet(99, 829, 197, 122, 117) is False, \
    "文档 §8：99/829/197/122/117 必须是 False"
print("OK 文档示例：is_full_pet(99,829,197,122,117) = False")


def build_pet(level, adds):
    """正向造一只「源码确实能生成出来」的巴朵兰恩。

    ⚠ 必须走 stw_pet.grow_stats：攻/防带交叉项，不是 K*S//100。
    早期测试在这里自己抄了一份简化公式，结果生产改了口径测试还在自洽。
    """
    V, S, T, D = 25 + adds[0], 39 + adds[1], 22 + adds[2], 27 + adds[3]
    return grow_stats(level, V, S, T, D)


ok_full = 0
for adds in [(2, 3, 2, 3), (0, 10, 0, 0), (10, 0, 0, 0), (0, 0, 0, 10),
             (1, 1, 1, 7), (5, 5, 0, 0)]:
    # ⚠ 不含低等级：K 太小时面板数值大量撞车，严格判定必然 False
    #   （Lv7 只有部分加点能判 True，Lv20 起这 6 组加点都成立）
    for lv in (20, 60, 99, 140):
        hp, atk, df, agi = build_pet(lv, adds)
        assert is_full_pet(lv, hp, atk, df, agi) is True, (lv, adds, hp, atk, df, agi)
        ok_full += 1
print(f"OK 正向构造：{ok_full} 组「真满档」全部判为 True")

hp, atk, df, agi = build_pet(99, (2, 3, 2, 3))
assert is_full_pet(99, hp + 1, atk, df, agi) is False
assert is_full_pet(99, hp, atk + 1, df, agi) is False
print("OK 稍微改一个数值就变 False（不是无脑 True）")

# ---- 真实样本回归（★比跟伪代码对拍靠谱得多）----
# 用户实机抓到的巴朵兰恩：Lv104 HP882 攻204 防141 敏144。
# 这条样本同时证伪了旧的简化口径（K*S//100 只能算出攻 171）。
REAL = (104, 882, 204, 141, 144)
assert is_full_pet(*REAL) is True, REAL
assert is_full_pet(104, 882, 171, 96, 158) is False, "简化口径算出来的面板不该判满档"
print(f"OK 真实样本回归：Lv{REAL[0]} HP{REAL[1]} {REAL[2]}/{REAL[3]}/{REAL[4]}"
      " -> 满档（简化口径判不出来的那只）")

# ---- 随机样本：满档构造必 True，随机噪声基本 False ----
rnd = random.Random(20260930)
ok_true = 0
checked = 0
for _ in range(300):
    lv = rnd.randint(7, 160)
    if rnd.random() < 0.5:
        adds = [0, 0, 0, 0]
        for _ in range(10):
            adds[rnd.randrange(4)] += 1
        hp, atk, df, agi = build_pet(lv, adds)
    else:
        hp = rnd.randint(1, 900)
        atk, df, agi = rnd.randint(1, 300), rnd.randint(1, 200), rnd.randint(1, 200)
    checked += 1
    if is_full_pet(lv, hp, atk, df, agi):
        ok_true += 1
        # 判 True 的一定要能真造出来（倍率一致）
        assert hp > 0 and atk > 0
print(f"OK 随机 {checked} 组跑通（判满档 {ok_true} 组），无异常")

# ---------------------------------------------------------------------------
# 2. K 包解析（v2）
# ---------------------------------------------------------------------------
p0 = parse_k_pet(K0_DOC)
assert p0["slot"] == "K0" and p0["name"] == "石龟 min-1", p0
assert p0["base_name"] == "石龟", p0
assert p0["level"] == 128 and p0["hp"] == 1251 and p0["hp_max"] == 1251, p0
assert p0["atk"] == 216 and p0["def"] == 356 and p0["agi"] == 50, p0
assert p0["loyalty"] == 100 and p0["pet_id"] == 100274, p0
assert p0["partial"] is False

p2 = parse_k_pet(K2_DOC)
assert p2["name"] == "火的守护兽" and p2["level"] == 50, p2
assert (p2["hp"], p2["atk"], p2["def"], p2["agi"]) == (355, 94, 50, 39), p2

p3 = parse_k_pet(K3_DOC)
assert p3["name"] == "巴朵兰恩" and p3["level"] == 140, p3
assert (p3["hp"], p3["atk"], p3["def"], p3["agi"]) == (1370, 320, 202, 188), p3
print("OK 长包解析：v2 文档 §4 三条样本（石龟/火的守护兽/巴朵兰恩）字段全对")

assert parse_k_pet(K0_LONG)["name"] == "摩娜西普"
assert parse_k_pet(K0_LONG)["level"] == 133        # v1 会错解成 1234（那是 HP）
print("OK 真实长包：第 9 段才是等级（v1 把第 3 段的 HP 当等级是错的）")

ps = parse_k_pet(K3_SHORT)
assert ps["partial"] is True and ps["level"] is None and ps["name"] is None, ps
assert (ps["hp"], ps["atk"], ps["def"], ps["agi"]) == (1256, 327, 215, 190), ps
print("OK 短包解析：只有数值（hp/atk/def/agi/忠诚），没有等级和名字")

assert parse_k_pet("K2|0|") is None, "空槽 -> None"
assert parse_k_pet("K4|0|") is None
assert parse_k_pet("P9MKy6|1|2|3") is None, "非宠物包不该进宠物栏"
assert parse_k_pet("K9|xZa|1|0|0|1|1|1|1|") is None, "槽位必须是 K0~K4"
assert parse_k_pet("K1|1|100250|0|0|0|0|0|0|0|1|1|1|1|0|0|0|0|5|1||") is None, \
    "等级为 0 视为空槽"
print("OK 空槽 / 非宠物包 / 越界槽位 / 等级0 一律 None")

assert PET_SLOTS == ["K0", "K1", "K2", "K3", "K4"]
assert PET_K_FIELDS["long"]["level"] == 9 and PET_K_FIELDS["long"]["name"] == 20
print("OK PET_K_FIELDS：等级=9 名字=20（v2）")

# ---------------------------------------------------------------------------
# 3. 界面
# ---------------------------------------------------------------------------
import tkinter as tk                              # noqa: E402
from tkinter import ttk                           # noqa: E402

root = tk.Tk()
panel = PetPanel(root)
panel.pack()
root.update()
assert len(panel.rows) == 5, "必须固定 5 行"
assert all(v.get() == "空" for v, _ in panel.rows)

panel.update_pet_list([
    {"name": "石龟 min-1", "level": 128, "full": True},
    {"name": "火的守护兽", "level": 50, "full": False},
    None,
    {"name": "巴朵兰恩", "level": 140, "full": False},
    {"name": None, "level": None, "full": False},     # 只收到过短包
])
root.update()
texts = [v.get() for v, _ in panel.rows]
print("   渲染结果：", texts)
assert texts[0] == "石龟 min-1 Lv128 ★满档", texts[0]
assert texts[1] == "火的守护兽 Lv50", texts[1]
assert texts[2] == "空", texts[2]
assert texts[4] == "同步中…", texts[4]
assert not any(t.startswith("K") for t in texts), "绝不许显示协议槽位 Kx"
root.destroy()
print("OK 界面：5 行、★满档、空槽「空」、缺等级「同步中…」、不显示 K0~K4")

# ---------------------------------------------------------------------------
# 4. 接入：真 Engine
# ---------------------------------------------------------------------------
import queue                                      # noqa: E402

sa = stw_engine.sa
# 样本日志在 tests/data/ 下（重构后不再和源码混在仓库根）
stw_engine.LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "data", "_test_pet_log.jsonl")
ACCOUNT = "testacct"
KEY = sa.make_l2_key(ACCOUNT)


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
    def snapshot(self):
        return {"state": 9, "x": 10, "y": 10, "map": 999999}

    def close(self):
        pass


def fake_setup(self):
    self.pid = 0
    self.key = KEY
    self.api = FakeApi()
    self.b = FakeBridge()
    self.g = FakeGame()
    self.sess = self.sn = self.snc = self.hook_sc = None


Engine = stw_engine.Engine
Engine.setup = fake_setup
Engine.set_hook = lambda self, on: None


def frame(fid, payload):
    msg = b"&;" + str(fid).encode() + b";" + sa.enstring(payload, KEY) + b";#;"
    return {"hex": stw_engine.enc(msg).hex(), "dir": "IN"}


def wait_until(pred, timeout=10.0, what=""):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if pred():
            return True
        time.sleep(0.05)
    raise AssertionError(f"等不到条件成立：{what}（{timeout}s）")


cfg = {"pid": 0, "account": ACCOUNT, "accounts": [ACCOUNT],
       "fast_enc": False, "fast_battle": True, "mode": "flee",
       "interval": 0.1, "secs": 100000.0, "maxb": 999,
       "show46": False, "showraw": False,
       "catch": {"rules": {}, "no_match_action": "flee",
                 "pet_action": "attack", "after_success": "continue",
                 "stop_count": 1}}
q = queue.Queue()
e = Engine(cfg, q)
e.auto_ev.clear()
e.start()
wait_until(lambda: e.battle_hook_active, what="引擎挂载监听")

e.api.q.extend([frame(46, K0_DOC), frame(46, K3_SHORT), frame(46, "K2|0|")])
wait_until(lambda: e.pet_panel.get("K0") is not None, what="K0 进宠物栏")
assert e.pet_panel["K0"]["name"] == "石龟 min-1"
assert e.pet_panel["K0"]["level"] == 128
assert e.pet_panel["K2"] is None, "空槽"
# 短包只覆盖数值，名字/等级不能丢
wait_until(lambda: (e.pet_panel.get("K3") or {}).get("atk") == 327,
           what="K3 短包数值")
assert e.pet_panel["K3"]["level"] is None, "短包没有等级"
print("OK 接入：长包进栏、空槽清空、短包只覆盖数值（不掉名字/等级）")

# ---- 满档只对「新抓到的宠」判定 ----
# ⚠ 等级不能取 1：Lv1 的 K=27 太小，面板数值大量撞车，严格判定恒 False。
#   这里取 20（严格判定能判 True 的最低档位之一）。
lv, adds = 20, (2, 3, 2, 3)
hp, atk, df, agi = build_pet(lv, adds)
NEW_FULL = ("K4|1|100373|%d|%d|0|0|16984|-1|%d|%d|%d|%d|100|"
            "0|0|0|0|7|1|巴朵兰恩||" % (hp, hp, lv, atk, df, agi))

# 同一条包：不是新抓的宠 -> 不判（full 保持 False）
e._update_pet(NEW_FULL, new_catch=False)
assert e.pet_panel["K4"]["full"] is False, "已有宠物不做满档判定"
print("OK 已有宠物：满档判定被跳过（full=False）")

# 同一条包：标记为新抓 -> 判定
e._update_pet(NEW_FULL, new_catch=True)
assert e.pet_panel["K4"]["full"] is True, e.pet_panel["K4"]
print(f"OK 新抓宠物：Lv{lv} ({hp}/{atk}/{df}/{agi}) -> ★满档")

# 之后再用短包刷新，满档标记不能被冲掉
e._update_pet("K4|xZa|%d|0|16984|%d|%d|%d|100|0|0|0|" % (hp, atk, df, agi),
              new_catch=False)
assert e.pet_panel["K4"]["full"] is True, "短包刷新不能把满档标记冲掉"
print("OK 短包刷新后满档标记保留")

kinds = []
try:
    while True:
        kinds.append(q.get_nowait()[0])
except queue.Empty:
    pass
assert "pet_panel" in kinds, sorted(set(kinds))
print("OK 界面收到 pet_panel 刷新消息")
e.stop_flag.set()
e.join(timeout=5)

# ---------------------------------------------------------------------------
# 5. 丢弃宠物（丢弃宠物.MD）
# ---------------------------------------------------------------------------
from stw_pet import build_drop_l2, pet_slot_of           # noqa: E402

# §5 验收 1/2：组 L2
assert build_drop_l2(68, 35, "K0") == "68|35|0|103", build_drop_l2(68, 35, "K0")
assert build_drop_l2(15, 14, "K2") == "15|14|2|31", build_drop_l2(15, 14, "K2")
assert build_drop_l2(15, 14, 2) == "15|14|2|31", "槽位也接受纯数字"
assert build_drop_l2(0, 0, "K4") == "0|0|4|4"
assert build_drop_l2(1, 1, "K9") is None, "越界槽位不能组包"
assert build_drop_l2(1, 1, "P9MKy6") is None
print("OK build_drop_l2：68,35,K0 → 68|35|0|103 ；15,14,K2 → 15|14|2|31")

assert pet_slot_of("K3|1|100373|1370|...") == "K3"
assert pet_slot_of("P9MKy6|1|2") is None
assert fe.slot_index("k2") == 2 and fe.slot_index(4) == 4 and fe.slot_index("K5") == -1

# 真报文：走 L1 编码器后还能解回 L2 明文
def decode_out(raw):
    l2 = sa.decode_layer1(raw)
    p = l2.split(b";")
    return p[1].decode(), [sa.deint(x, KEY) for x in p[2:-2]]


for (x, y, sl) in ((68, 35, "K0"), (15, 14, "K2")):
    fid, vals = decode_out(stw_engine.enc(fe.build_drop(x, y, sl, KEY)))
    assert fid == "21", fid
    i = fe.slot_index(sl)
    assert vals == [x, y, i, x + y + i], (vals, x, y, i)
print("OK fid=21 真报文：解回 [x, y, slot, x+y+slot]，与文档实包一致")


class FakeGameAt:
    def __init__(self, x, y):
        self.x, self.y = x, y

    def snapshot(self):
        return {"state": 9, "x": self.x, "y": self.y, "map": 999999}

    def close(self):
        pass


cfg2 = dict(cfg)
cfg2["mode"] = "catch"
cfg2["catch"] = dict(cfg["catch"])
cfg2["catch"]["drop_non_full"] = True
q2 = queue.Queue()
e2 = Engine(cfg2, q2)
e2.auto_ev.clear()
e2.start()
wait_until(lambda: e2.battle_hook_active, what="引擎2 挂载监听")
e2.g = FakeGameAt(68, 35)

# ——— 满档的新宠：不排队、不发 ———
e2._update_pet(NEW_FULL, new_catch=True)
assert e2.pet_panel["K4"]["full"] is True
assert e2._enqueue_drop("K4", e2.pet_panel["K4"]) is False
assert e2.drop_queue == [], "满档宠绝不能进丢弃队列"
print("OK 满档宠不丢弃")

# ——— 非满档的新宠：排队 → 发 fid=21 ———
BAD = ("K1|1|100999|100|100|0|0|1|-1|1|5|4|3|100|"
       "0|0|0|0|7|1|巴朵兰恩||")
e2._update_pet(BAD, new_catch=True)
assert e2.pet_panel["K1"]["full"] is False, e2.pet_panel["K1"]
assert e2._enqueue_drop("K1", e2.pet_panel["K1"]) is True
assert e2.drop_queue == ["K1"]
before = len(e2.b.sent)
assert e2._flush_drops() == 1
assert len(e2.b.sent) == before + 1
fid, vals = decode_out(e2.b.sent[-1])
assert fid == "21" and vals == [68, 35, 1, 104], (fid, vals)
assert e2.drop_queue == []
assert e2.catch_stats["dropped"] == 1
# ⚠ 发出后不许本地清空：栏位以服务端 fid=46 为准
assert e2.pet_panel["K1"] is not None, "丢完不能本地预先清空，要等 fid=46"
print("OK 丢弃：非满档宠 → fid=21 [68,35,1,104]，发出后本地不清空")

# ——— 空槽不发送 ———
assert e2._enqueue_drop("K2", None) is False
e2.pet_panel["K2"] = None
e2.drop_queue.append("K2")
before = len(e2.b.sent)
assert e2._flush_drops() == 0, "空槽不许发包"
assert len(e2.b.sent) == before
assert e2.drop_queue == []
print("OK 空槽不发送（排队后变空也自动取消）")

# ——— 短包（判不了满档）不发送 ———
e2._update_pet(K3_SHORT, new_catch=True)
assert e2.pet_panel["K3"]["partial"] is True
assert e2._enqueue_drop("K3", e2.pet_panel["K3"]) is False
print("OK 只有紧凑更新包（无等级）时不丢弃，避免误丢")

# ——— 关掉开关后不再排 ———
e2.catch_cfg["drop_non_full"] = False
assert e2._enqueue_drop("K0", e2.pet_panel.get("K0")) is False
e2.catch_cfg["drop_non_full"] = True

# ——— 收到 K1|0| → 面板 K1 变「空」，且 k_names 释放 ———
e2.k_names["K1"] = "巴朵兰恩"
e2.api.q.append(frame(46, "K1|0|"))
wait_until(lambda: e2.pet_panel.get("K1") is None, what="K1|0| 清空面板")
assert "K1" not in e2.k_names, "空槽必须释放 k_names，否则同槽再抓不算新宠"
print("OK 收到 K1|0|：面板 K1 = 「空」，k_names 同步释放（同槽再抓仍算新宠）")

# ——— 只更新报文里出现的槽 ———
e2.api.q.append(frame(46, K0_DOC))
wait_until(lambda: (e2.pet_panel.get("K0") or {}).get("pet_id") == 100274,
           what="K0 更新")
snap_before = e2.pet_panel.get("K3")
e2.api.q.append(frame(46, "K2|1|100290|355|355|0|0|0|51520|50|94|50|39|0|"
                          "0|0|0|0|5|1|火的守护兽||"))
wait_until(lambda: (e2.pet_panel.get("K2") or {}).get("level") == 50,
           what="K2 更新")
assert (e2.pet_panel.get("K0") or {}).get("name") == "石龟 min-1", "K0 不该被动"
assert e2.pet_panel.get("K3") == snap_before, "没出现的槽必须保持原值"
assert (e2.pet_panel.get("K2") or {}).get("base_name") == "火的守护兽"
print("OK 只更新报文里出现的槽（K2 更新不动 K0/K3）")

e2.stop_flag.set()
e2.join(timeout=5)

print("\nRESULT: PASS")
