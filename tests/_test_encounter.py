"""受控验证：先空等看会不会自然遇敌，再发一个 gc*10 包看是否立刻进战斗。"""
import importlib.util
import os
import sys
import time

# 仓库根 + stw_ui 包目录进 sys.path（从 __file__ 推，不写死绝对路径）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "stw_ui"))
sys.path.insert(0, _ROOT)
import auto_encounter as ae  # noqa: E402
import stw_config  # noqa: E402

# ⚠ 不要写死 v30：那份文件已不存在，版本号会随抓包脚本升级
CODEC = stw_config.resolve_codec()
PID = 57244
ACCOUNT = "<你的账号>"

spec = importlib.util.spec_from_file_location("sa_codec", CODEC)
sa = importlib.util.module_from_spec(spec)
sys.modules["sa_codec"] = sa
spec.loader.exec_module(sa)
import fast_encounter as fe  # noqa: E402


def watch(g, secs, tag):
    t0 = time.time()
    seen = set()
    while time.time() - t0 < secs:
        s = g.snapshot()
        seen.add(s["state"])
        if s["state"] == 10:
            print(f"  [{tag}] +{time.time()-t0:5.1f}s  *** state=10 战斗 ***  x={s['x']} y={s['y']}")
            return True, s
        time.sleep(0.3)
    print(f"  [{tag}] {secs}s 内状态集合={sorted(seen)} 无遇敌")
    return False, g.snapshot()


g = ae.Game(PID)
print("阶段1：空等 20s，看会不会自然遇敌")
hit, s = watch(g, 20.0, "基线")
print(f"  当前 x={s['x']} y={s['y']} map={s['map']} state={s['state']}")

if s["state"] != 9:
    print("  不在地图上（state!=9），无法测试，退出")
    sys.exit(1)

key = sa.make_l2_key(ACCOUNT)
msg = fe.build_walk(s["x"], s["y"], fe.fast_encounter_path(20), key)
wire = sa.encode_layer1(msg)
print(f"\n阶段2：发一个包  L2={msg.decode()}")
print(f"  L1={wire.hex()}")

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
r = b.send(wire)
print(f"  发送结果: {r}")
b.close()

print("\n阶段3：观察 15s")
hit2, s2 = watch(g, 15.0, "发包后")
print(f"\n结论: 基线遇敌={hit}  发包后遇敌={hit2}")
g.close()
