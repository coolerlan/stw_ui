"""验证服务器是否真的接受并执行我们伪造的移动包。

用一个净位移 != 0 的路径（默认 cccc = 向东 4 步），
看角色坐标是否跟着变。若变了，说明报文被接受；
遇敌与否只是概率问题，不能用来判断报文对不对。
"""
import importlib.util
import os
import sys
import time

# 仓库根 + stw_ui 包目录进 sys.path（从 __file__ 推，不写死绝对路径）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "stw_ui"))
sys.path.insert(0, _ROOT)
import auto_encounter as ae  # noqa: E402
import fast_encounter as fe  # noqa: E402

# ⚠ 不要在这里写死 vNN 版本号：codec 一改名（v30 → v31）本脚本就起不来。
# 统一走 stw_config.resolve_codec()：优先用 CODEC，不存在则自动挑最高版本。
from stw_config import resolve_codec  # noqa: E402

PID = 57244
ACCOUNT = "<你的账号>"
PATH = sys.argv[1] if len(sys.argv) > 1 else "cccc"
OBS = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0

spec = importlib.util.spec_from_file_location("sa_codec", resolve_codec())
sa = importlib.util.module_from_spec(spec)
sys.modules["sa_codec"] = sa
spec.loader.exec_module(sa)

g = ae.Game(PID)


def track(secs, tag):
    t0 = time.time()
    pts = []
    while time.time() - t0 < secs:
        s = g.snapshot()
        pts.append((round(time.time() - t0, 1), s["x"], s["y"], s["state"]))
        time.sleep(0.3)
    print(f"  [{tag}] " + " ".join(f"{t}s({x},{y},st{st})" for t, x, y, st in pts[::3]))
    print(f"  [{tag}] 首={pts[0][1:]} 末={pts[-1][1:]}")
    return pts


print(f"稳定观察 6s（判断角色是否在被别的东西移动）")
track(6.0, "静默")

s = g.snapshot()
x0, y0 = s["x"], s["y"]
print(f"\n起点 ({x0},{y0}) state={s['state']}  发送路径 '{PATH}' ({len(PATH)} 步)")

key = sa.make_l2_key(ACCOUNT)
msg = fe.build_walk(x0, y0, PATH, key)
wire = sa.encode_layer1(msg)
print(f"  L2={msg.decode()}")

b = sa.FridaSocketBridge(PID, 9065)
st = b.status()
w = 0.0
while not st.get("ready") and w < 60:
    time.sleep(2.0)
    w += 2.0
    st = b.status()
if not st.get("ready"):
    print("  网桥未就绪，放弃")
    sys.exit(1)
print(f"  发送: {b.send(wire)}")
b.close()

pts = track(OBS, "发包后")
g.close()

moved = any((px, py) != (x0, y0) for _, px, py, _ in pts)
print(f"\n结论: 角色{'发生了移动 -> 报文被服务器接受' if moved else '没动 -> 报文可能被丢弃或坐标不符'}")
