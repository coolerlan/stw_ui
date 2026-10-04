"""
STW 风格「快速遇敌」：直接发 fid=1 移动包，不点鼠标。

原理
----
STW 的快速遇敌不是模拟点击，而是直接向服务器发一条移动包：
    fid = 1，字段 = [x, y, path, x+y+len(path)]
其中 x,y 是**起点**格子，path 每字符一步。STW 用
    path = "gc" * 10        (20 步：西、东、西、东……)
净位移为 0 —— 角色原地来回走，一步一次遇敌判定，遇敌率 x20。

这正好对应 STW 里硬编码的两个点击点 (0x120,0x108) / (0x160,0xD8)：
换算成格子就是 (-1,0)='g' 和 (+1,0)='c'。

方向表（由抓包逐条反推，209 条样本全部吻合）
-------------------------------------------
    a=(0,-1) 北    b=(+1,-1) 东北   c=(+1,0) 东    d=(+1,+1) 东南
    e=(0,+1) 南    f=(-1,+1) 西南   g=(-1,0) 西    h=(-1,-1) 西北

用法
----
  python fast_encounter.py --selftest              # 用抓包校验编解码器
  python fast_encounter.py --dry-run               # 只打印报文，不发送
  python fast_encounter.py --account <你的账号> --once # 发一次
  python fast_encounter.py --account <你的账号>        # 持续快速遇敌
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import time

# ⚠ 不要写死 vNN 版本号：codec 一改名（v30 → v31）--codec 默认值就指向空文件。
# 统一走 stw_config.resolve_codec()：优先用 CODEC，不存在则自动挑最高版本。
from stw_config import resolve_codec  # noqa: E402

CODEC_PATH = resolve_codec()
CAPTURE = "sa2903_visible_encounter.jsonl"
DEFAULT_PORT = 9065

# 方向字符 -> (dx, dy)
DIR = {
    "a": (0, -1), "b": (1, -1), "c": (1, 0), "d": (1, 1),
    "e": (0, 1), "f": (-1, 1), "g": (-1, 0), "h": (-1, -1),
}
NAME = {
    "a": "北", "b": "东北", "c": "东", "d": "东南",
    "e": "南", "f": "西南", "g": "西", "h": "西北",
}


def load_codec(path: str = CODEC_PATH):
    spec = importlib.util.spec_from_file_location("sa_codec", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["sa_codec"] = mod          # dataclass 需要模块已在 sys.modules 里
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------
# L2 字段编码
# --------------------------------------------------------------------------
def sextets(data: bytes) -> list[int]:
    """把字节串按 LSB-first 切成 6 位组（无符号流式累加）。

    重要：必须用**无符号**移位。4 字节整数要 6 个 sextet，最后一组只剩
    高 2 位，所以末位取值只能是 0..3；用带符号算术右移会得到 63（符号扩展）。
    实测（PID 57244 线上抓到的真实包 x=7）：
        真实 = ql5hnd -> [63,63,15,62,63,3]   无符号 ✔
                          有符号 -> [63,63,15,62,63,63]  ✘
    解码值两者一样（deint 只取前 4 字节），所以只有逐字节比对才能发现。
    """
    acc = 0
    nbits = 0
    vals: list[int] = []
    for b in data:
        acc |= int(b) << nbits
        nbits += 8
        while nbits >= 6:
            vals.append(acc & 0x3F)
            acc >>= 6
            nbits -= 6
    if nbits:
        vals.append(acc & 0x3F)
    while len(vals) > 1 and vals[-1] == 0:
        vals.pop()
    return vals


def encode_field(vals: list[int], key: str | bytes, mode: str) -> bytes:
    """字符串字段减 key，整数字段加 key（与 _decode64 的 shr/shl 对应）。"""
    if isinstance(key, str):
        key = key.encode("latin1", "replace")
    table = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}"
    out = bytearray()
    for i, v in enumerate(vals):
        k = key[i % len(key)]
        idx = (v + k) % 64 if mode == "int" else (v - k) % 64
        out.append(table[idx])
    return bytes(out)


def enint(value: int, key: str | bytes) -> bytes:
    raw = int(value).to_bytes(4, "little", signed=True)
    t2 = bytes((raw[1], raw[3], raw[0], raw[2]))
    packed = (int.from_bytes(t2, "little") ^ 0xFFFFFFFF) & 0xFFFFFFFF
    return encode_field(sextets(packed.to_bytes(4, "little")), key, "int")


def enstring(value: str | bytes, key: str | bytes) -> bytes:
    if isinstance(value, str):
        value = value.encode("gb18030", "replace")
    return encode_field(sextets(value), key, "string")


def build_walk(x: int, y: int, path: str, key: str | bytes, fid: int = 1) -> bytes:
    """组装 L2 报文： &;<fid>;<x>;<y>;<path>;<x+y+len>;#; """
    n = x + y + len(path)
    return (b"&;" + str(fid).encode() + b";" +
            enint(x, key) + b";" +
            enint(y, key) + b";" +
            enstring(path, key) + b";" +
            enint(n, key) + b";#;")


def fast_encounter_path(steps: int = 20) -> str:
    """STW 的原地来回走路径：西/东交替，净位移 0。

    STW 客户端 dump 出来的 399 条 fid=1 全是这一条（x=29 y=74 n=123）：
        [0]=29 [1]=74 [2]=gcgcgcgcgcgcgcgcgcgc [3]=123
    与我们构造的完全一致。
    """
    return ("gc" * (steps // 2)) + ("g" if steps % 2 else "")


# --------------------------------------------------------------------------
# 战斗指令（fid=14）
# --------------------------------------------------------------------------
# 格式： &;14;<命令字符串>;<命令长度>;#;
#   实测（你手动点逃跑时客户端发的）： E        checksum=1   -> 逃跑
#                                     W|FF|FF  checksum=7   -> 宠物不行动
#   STW dump 里用的是攻击：           H|F       checksum=3   -> 攻击 15 号位
#                                     W|1|F     checksum=5   -> 宠物攻击
# ⚠ 这是「旧路径」的指令表：目标写死成 F，且整场只发一次
#   （--battle attack 会在嗅到 fid=66/7 时立刻发，或看 state==10 补发一次），
#   不是按每回合 BA 驱动。
#   stw_ui.py 的新应答机用自己的 ROUND_CMDS（带 {t} 占位符，目标由最近一次
#   BC 里「存在且 hp>0」的敌方槽位动态选出），不要用这张表，
#   也不要用 `fast_encounter.py --battle attack` 去验证新应答机。
BATTLE_CMDS = {
    "flee": ("E", "W|FF|FF"),
    "attack": ("H|F", "W|1|F"),
    "catch": ("C|F", "W|FF|FF"),  # 捕捉指令：C=Catch, F=目标位置
}


def build_battle_cmd(cmd: str, key: str | bytes, fid: int = 14) -> bytes:
    """组装战斗指令报文 &;14;<cmd>;<len(cmd)>;#;"""
    return (b"&;" + str(fid).encode() + b";" +
            enstring(cmd, key) + b";" +
            enint(len(cmd), key) + b";#;")


# --------------------------------------------------------------------------
# 丢弃宠物（fid=21）—— 丢弃宠物.MD §1
# --------------------------------------------------------------------------
# 格式： &;21;<x>;<y>;<slot>;<x+y+slot>;#;
#   L2 明文： x|y|slot|x+y+slot      slot: 0=K0 … 4=K4
#   实包：    丢 K0 @ (68,35) -> 68|35|0|103
#             丢 K2 @ (15,14) -> 15|14|2|31
# ⚠ 只丢**有宠**的槽；不带名字 / pet_id / uid，别多塞字段。
#   发出去之后**不许本地清空**，等服务端 S>C fid=46（Kx|0|）来改状态。
def slot_index(slot) -> int:
    """"K2" / "k2" / 2 -> 2；非法槽位返回 -1。"""
    if isinstance(slot, int):
        return slot if 0 <= slot <= 4 else -1
    s = str(slot).strip().upper()
    if len(s) == 2 and s[0] == "K" and s[1] in "01234":
        return int(s[1])
    return -1


def build_drop(x: int, y: int, slot, key: str | bytes, fid: int = 21) -> bytes:
    """组装丢弃报文 &;21;<x>;<y>;<slot>;<x+y+slot>;#;"""
    i = slot_index(slot)
    if i < 0:
        raise ValueError(f"非法宠物槽位：{slot!r}")
    return (b"&;" + str(fid).encode() + b";" +
            enint(int(x), key) + b";" +
            enint(int(y), key) + b";" +
            enint(i, key) + b";" +
            enint(int(x) + int(y) + i, key) + b";#;")


# --------------------------------------------------------------------------
# 自检
# --------------------------------------------------------------------------
def selftest(sa, path: str = CAPTURE) -> int:
    key = sa.make_l2_key("<STW的账号>")
    rows = [json.loads(l) for l in open(path, encoding="utf-8", errors="replace")]
    pro = [r for r in rows
           if r.get("type") == "protocol" and str(r.get("fid")) == "1"
           and r.get("field_prefix_hex")]

    ok = bad = 0
    for r in pro:
        m = re.search(r"x=(-?\d+) y=(-?\d+) path='([^']*)'", str(r.get("description")))
        if not m:
            continue
        x, y, p = int(m.group(1)), int(m.group(2)), m.group(3)
        h = r["field_prefix_hex"]
        want = [bytes.fromhex(v) for v in h]
        got = [enint(x, key), enint(y, key), enstring(p, key), enint(x + y + len(p), key)]
        if got == want:
            ok += 1
        else:
            bad += 1
            if bad <= 5:
                print(f"  不符 x={x} y={y} path={p}")
                for i, (g, w) in enumerate(zip(got, want)):
                    print(f"     字段{i}: 构造={g!r} 真实={w!r}")

    print(f"  编码器自检（对照 {path}）: {ok} 符 / {bad} 不符")
    if bad == 0:
        msg = build_walk(54, 53, "C", key)
        wire = sa.encode_layer1(msg, rn=12345)
        print(f"  样例 L2 : {msg.decode()}")
        print(f"  样例 L1 : {wire.hex()}")
        print(f"  回环一致 : {sa.decode_layer1(wire) == msg}")
    return bad


# --------------------------------------------------------------------------
# 进程安全
# --------------------------------------------------------------------------
def stw_child_pids() -> set[int]:
    try:
        import psutil
    except ImportError:
        return set()
    out = set()
    for p in psutil.process_iter(["pid", "name", "ppid"]):
        if (p.info["name"] or "").lower() != "sa_2903.exe":
            continue
        try:
            parent = psutil.Process(p.info["ppid"]).name().lower()
        except Exception:
            continue
        if "stw" in parent:
            out.add(p.info["pid"])
    return out


def pick_pid(explicit: int) -> int:
    blocked = stw_child_pids()
    import psutil
    mine = [p.info["pid"] for p in psutil.process_iter(["pid", "name"])
            if (p.info["name"] or "").lower() == "sa_2903.exe"
            and p.info["pid"] not in blocked]
    if explicit:
        if explicit in blocked:
            raise SystemExit(f"PID {explicit} 是 STW0.30.exe 的子进程，拒绝操作")
        return explicit
    if not mine:
        raise SystemExit("没找到可操作的客户端（全部是 STW 子进程）")
    print(f"  可用客户端 PID={mine} （已排除 STW 子进程 {sorted(blocked)}）")
    return mine[0]


def main() -> int:
    ap = argparse.ArgumentParser(description="STW 风格快速遇敌：直接发 fid=1 移动包")
    ap.add_argument("--account", help="账号，L2 key = 账号 + 'bing'")
    ap.add_argument("--pid", type=int, help="客户端 PID，默认自动挑非 STW 的")
    ap.add_argument("--steps", type=int, default=20, help="路径步数，默认 20（STW 用 20）")
    ap.add_argument("--interval", type=float, default=0.35, help="发包间隔秒")
    ap.add_argument("--count", type=int, default=0, help="发包次数，0=不限")
    ap.add_argument("--once", action="store_true", help="只发一次")
    ap.add_argument("--dry-run", action="store_true", help="只打印报文，不发送")
    ap.add_argument("--selftest", action="store_true", help="用抓包校验编解码器")
    ap.add_argument("--codec", default=CODEC_PATH)
    ap.add_argument("--wait", type=float, default=60.0,
                    help="等游戏自己发一个包以便抓到 socket，最多等这么久（秒）")
    ap.add_argument("--battle", choices=("flee", "attack", "catch", "none"), default="flee",
                    help="进战斗后自动干什么：flee=逃跑(默认,和你手动点的一样) "
                         "attack=自动攻击(STW 的做法) catch=捕捉 none=不管")
    ap.add_argument("--seconds", type=float, default=0.0, help="运行时长，0=一直到 Ctrl+C")
    args = ap.parse_args()

    sa = load_codec(args.codec)

    if args.selftest:
        return 1 if selftest(sa) else 0

    if not args.account:
        raise SystemExit("需要 --account（STW 那个是 <STW的账号>，你自己开的是 <你的账号>）")

    key = sa.make_l2_key(args.account)
    pid = pick_pid(args.pid)

    path = fast_encounter_path(args.steps)
    x = y = None

    # 若装了 auto_encounter 就顺带读真实坐标，否则用占位值
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import auto_encounter as ae
        g = ae.Game(pid)
        s = g.snapshot()
        x, y = s["x"], s["y"]
        g.close()
    except Exception as e:
        print(f"  读坐标失败({e})，改用占位 (0,0)")
        x = y = 0

    msg = build_walk(x, y, path, key)
    wire = sa.encode_layer1(msg)
    assert sa.decode_layer1(wire) == msg, "L1 回环失败"

    print(f"  PID={pid}  账号={args.account}  key={args.account}bing")
    print(f"  起点=({x},{y})  路径={path} ({args.steps} 步, 净位移 0)")
    print(f"  L2: {msg.decode()}")
    print(f"  L1: {wire.hex()}  ({len(wire)} 字节)")

    if args.dry_run:
        print("  [DRY RUN] 不发送")
        return 0

    bridge = sa.FridaSocketBridge(pid, DEFAULT_PORT)

    # 游戏挂机时发包很稀疏（十几秒一次 keepalive），
    # 网桥必须等它自己发一个包才能认出 socket，所以要轮询等一会儿。
    st = bridge.status()
    waited = 0.0
    while not st.get("ready") and waited < args.wait:
        time.sleep(2.0)
        waited += 2.0
        st = bridge.status()
    print(f"  网桥: {st}  (等了 {waited:.0f}s)")
    if not st.get("ready"):
        print("  网桥没找到游戏 socket，放弃发送")
        bridge.close()
        return 1

    # 战斗指令先算好，进战斗的瞬间就能立刻发出去
    battle_wire = []
    if args.battle != "none":
        for c in BATTLE_CMDS[args.battle]:
            m = build_battle_cmd(c, key)
            battle_wire.append((c, sa.encode_layer1(m)))
        print(f"  战斗自动应答: {args.battle} -> {[c for c, _ in battle_wire]}")

    # 挂一个 sniff 用来「提前」发现开战包（fid=66 / fid=7），
    # 比轮询 state 更早，能在客户端把战斗界面画出来之前就把逃跑发出去。
    try:
        import frida
        from _frida_agent import AGENT
        sess = frida.attach(pid)
        sc = sess.create_script(AGENT)
        sc.load()
        sniffer = sc.exports_sync
    except Exception as e:
        print(f"  sniff 挂载失败({e})，退回只轮询 state")
        sniffer = None

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import auto_encounter as ae
    g = ae.Game(pid)

    n = 1 if args.once else (args.count or 0)
    i = 0
    t0 = time.time()
    last_walk = 0.0
    in_battle = False
    battle_acted = False
    battles = 0
    try:
        while True:
            if n and i >= n:
                break
            if args.seconds and time.time() - t0 > args.seconds:
                break

            # --- 1) 提前嗅探开战包，命中就立刻应答 ---
            if sniffer is not None:
                for r in sniffer.dump():
                    if r.get("dir") != "IN":
                        continue
                    try:
                        l2 = sa.decode_layer1(bytes.fromhex(r["hex"]))
                    except Exception:
                        continue
                    if not l2:
                        continue
                    parts = l2.split(b";")
                    if len(parts) < 2:
                        continue
                    fid = parts[1].decode("latin1", "replace")
                    if fid in ("66", "7") and battle_wire and not battle_acted:
                        in_battle = True
                        battle_acted = True
                        for c, w in battle_wire:
                            bridge.send(w)
                        print(f"  [{time.time()-t0:6.1f}s] 嗅到开战包 fid={fid} "
                              f"-> 立刻发 {args.battle} 指令")
                        break

            # --- 2) 状态机 ---
            s = g.snapshot()
            if s["state"] == 10:
                if not in_battle:
                    in_battle = True
                    battles += 1
                    print(f"  [{time.time()-t0:6.1f}s] 进战斗(轮询发现)")
                # 嗅探没抓到时兜底：也只发一次
                if battle_wire and not battle_acted:
                    battle_acted = True
                    for c, w in battle_wire:
                        bridge.send(w)
                    print(f"  [{time.time()-t0:6.1f}s] 补发 {args.battle} 指令")
            elif s["state"] == 9:
                if in_battle:
                    in_battle = False
                    battle_acted = False
                    print(f"  [{time.time()-t0:6.1f}s] 战斗结束")
                if time.time() - last_walk >= args.interval:
                    msg = build_walk(s["x"], s["y"], path, key)
                    wire = sa.encode_layer1(msg)
                    r = bridge.send(wire)
                    i += 1
                    last_walk = time.time()
                    print(f"  [{time.time()-t0:6.1f}s] 遇敌包 {args.steps} 步 "
                          f"从({s['x']},{s['y']}) -> {r.get('ok')}")
                    if not r.get("ok"):
                        break
                    if args.once:
                        break
            time.sleep(0.03)
    except KeyboardInterrupt:
        print("  已停止")
    finally:
        print(f"  合计: 遇敌包 {i} 次, 战斗 {battles} 次")
        bridge.close()
        g.close()
        if sniffer is not None:
            try:
                sc.unload(); sess.detach()
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
