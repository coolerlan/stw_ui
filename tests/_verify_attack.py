"""验证：战斗指令选「攻击」时，战斗记录是否正确。

做法：进一场战斗，发 attack 指令(H|F + W|1|F)，然后完整记录服务器回包，
重点看：
  1. BC 单位列表能否正确解析（我方/敌方、槽位）
  2. 攻击指令是否让战斗进入多回合
  3. BA / BH 里有没有伤害与血量变化（面板能不能据此更新）
  4. BE 是否正常结束、fid=8 是否补发
最后逃跑收尾，最多 --rounds 回合。
"""
import importlib.util
import json
import os
import sys
import time

# 仓库根 + stw_ui 包目录进 sys.path（从 __file__ 推，不写死绝对路径）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "stw_ui"))
sys.path.insert(0, _ROOT)

import auto_encounter as ae  # noqa: E402
import fast_encounter as fe  # noqa: E402
import frida  # noqa: E402
from _frida_agent import AGENT  # noqa: E402
from stw_protocol import parse_bc, units_to_slots  # noqa: E402

# 别写死 vNN：那份文件每次升级都改名，写死了 import 阶段就 FileNotFoundError
from stw_config import resolve_codec  # noqa: E402

CODEC = resolve_codec()
ACCOUNT = "<你的账号>"
MAX_ROUNDS = int(sys.argv[1]) if len(sys.argv) > 1 else 3
OUT = "attack_verify_log.jsonl"

spec = importlib.util.spec_from_file_location("sa_codec", CODEC)
sa = importlib.util.module_from_spec(spec)
sys.modules["sa_codec"] = sa
spec.loader.exec_module(sa)

pid = [r[0] for r in ae.list_clients() if not r[3]][0]
print(f"目标 PID={pid}")
key = sa.make_l2_key(ACCOUNT)
g = ae.Game(pid)

sess = frida.attach(pid)
sc = sess.create_script(AGENT)
sc.load()
api = sc.exports_sync
b = sa.FridaSocketBridge(pid, 9065)
st = b.status()
w = 0.0
while not st.get("ready") and w < 60:
    time.sleep(2.0)
    w += 2.0
    st = b.status()
print(f"网桥 ready={st.get('ready')}")


def send_cmd(c):
    b.send(sa.encode_layer1(fe.build_battle_cmd(c, key)))


def drain():
    """取出所有 IN 包，返回 [(fid, 明文)]"""
    out = []
    for r in api.dump():
        if r["dir"] != "IN":
            continue
        try:
            l2 = sa.decode_layer1(bytes.fromhex(r["hex"]))
        except Exception:
            continue
        if not l2:
            continue
        p = l2.split(b";")
        if len(p) < 3:
            continue
        fid = p[1].decode("latin1", "replace")
        try:
            v = sa.destring(p[2], key).decode("gb18030", "replace")
        except Exception:
            v = ""
        out.append((fid, v))
    return out


logfh = open(OUT, "a", encoding="utf-8")


def rec(kind, text):
    line = f"[{time.strftime('%H:%M:%S')}] {kind}: {text}"
    print(line)
    logfh.write(json.dumps({"t": time.time(), "kind": kind, "s": text},
                           ensure_ascii=False) + "\n")


# ---- 1. 快速遇敌直到进战斗 ----
rec("info", "开始快速遇敌")
in_battle = False
t0 = time.time()
while not in_battle and time.time() - t0 < 90:
    s = g.snapshot()
    if s["state"] == 9:
        msg = fe.build_walk(s["x"], s["y"], fe.fast_encounter_path(20), key)
        b.send(sa.encode_layer1(msg))
    for fid, v in drain():
        if fid == "7":
            rec("battle", f"遇敌 fid=7 -> {v}")
            in_battle = True
        elif fid == "15" and v.startswith("BC"):
            rec("bc", v[:80])
    time.sleep(0.4)

if not in_battle:
    rec("fail", "90s 内没遇敌，退出")
    sys.exit(1)

# ---- 2. 解析 BC ----
bc_units = None
t1 = time.time()
while time.time() - t1 < 5:
    for fid, v in drain():
        if fid == "15" and v.startswith("BC"):
            f = v.split("|")
            bc_units = parse_bc(f[1:])
            enemy, ally = units_to_slots(bc_units, "UV2D")
            rec("bc", f"解析出 {len(bc_units)} 个槽")
            for sl, nm, lv, hp, mx in ally:
                extra = ""
                rec("ally", f"[0x{sl:X}] {nm} Lv{lv} {hp}/{mx}{extra}")
            for r in ally:
                if len(r) > 5:
                    rec("ally", f"   附加 {r[5]}")
            for sl, nm, lv, hp, mx in enemy:
                rec("enemy", f"[0x{sl:X}] {nm} Lv{lv} {hp}/{mx}")
    if bc_units:
        break
    time.sleep(0.2)

# ---- 3. 发攻击指令，观察多回合 ----
rec("cmd", "发攻击指令 H|F + W|1|F")
for c in fe.BATTLE_CMDS["attack"]:
    send_cmd(c)

rounds = 1
last = time.time()
bh_seen = 0
ba_seen = 0
while time.time() - t1 < 40:
    for fid, v in drain():
        if fid == "15":
            tag = v.split("|")[0] if v else ""
            if tag == "BA":
                ba_seen += 1
                rec("BA", v[:100])
            elif tag == "BH":
                bh_seen += 1
                rec("BH", v[:100])
            elif tag == "BE":
                rec("BE", "战斗结束")
                time.sleep(0.3)
                b.send(sa.encode_layer1(fe.build_battle_cmd("W|FF|FF", key)))
                rec("done", f"总回合={rounds} BA={ba_seen} BH={bh_seen}")
                logfh.close()
                sc.unload()
                sess.detach()
                b.close()
                g.close()
                sys.exit(0)
            elif tag not in ("BC", "BP"):
                rec("other", f"fid=15 {tag} {v[:80]}")
        elif fid == "46":
            rec("46", v[:70])
    # 每 1.6s 补一回合（和 stw_ui 的 1.4*rounds 节奏接近）
    if time.time() - last > 1.6 and rounds < MAX_ROUNDS:
        for c in fe.BATTLE_CMDS["attack"]:
            send_cmd(c)
        rounds += 1
        rec("cmd", f"补第 {rounds} 回合攻击")
        last = time.time()
    time.sleep(0.15)

rec("warn", f"40s 未结束，强制逃跑（回合={rounds} BA={ba_seen} BH={bh_seen}）")
send_cmd("E")
time.sleep(0.5)
b.send(sa.encode_layer1(fe.build_battle_cmd("W|FF|FF", key)))
logfh.close()
sc.unload()
sess.detach()
b.close()
g.close()
