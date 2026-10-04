"""验证「账号自动校正后必须立刻用新 key」这个 bug 已修掉。

三件事：
  1. 同一条指令用不同 key 加密，字节流必须不同（说明 key 真的进了报文）
  2. 用旧 key 加密的东西，拿新 key 解不出来（说明旧 key 缓存会真出问题）
  3. stw_engine.py 的 Engine.run() 里不许再出现把 self.key 缓存成局部变量
     的写法，所有发包/解密都必须走 self.key
"""
import importlib.util
import re
import os
import sys

# 仓库根 + stw_ui 包目录进 sys.path（从 __file__ 推，不写死绝对路径）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "stw_ui"))
sys.path.insert(0, _ROOT)

import fast_encounter as fe  # noqa: E402

# 编码模块路径统一从 stw_config 取，别在测试里再抄一份绝对路径
# （你每次升级都会改版本号，抄一份就必然在某天 FileNotFoundError）
from stw_config import CODEC                            # noqa: E402
spec = importlib.util.spec_from_file_location("sa_codec", CODEC)
sa = importlib.util.module_from_spec(spec)
sys.modules["sa_codec"] = sa
spec.loader.exec_module(sa)

OLD_ACC, NEW_ACC = "<你的账号>", "<STW的账号>"
k_old = sa.make_l2_key(OLD_ACC)
k_new = sa.make_l2_key(NEW_ACC)

# ---- 1. 同指令不同 key -> 报文不同 ----
cmd = "W|1|F"
p_old = fe.build_battle_cmd(cmd, k_old)
p_new = fe.build_battle_cmd(cmd, k_new)
print("旧 key 报文:", p_old)
print("新 key 报文:", p_new)
assert p_old != p_new, "key 没进报文？那这个 bug 就不存在了"
print("OK 1: key 不同 -> 报文不同")

# ---- 2. 旧 key 加密，新 key 解不出来（反之亦然） ----
payload = sa.enstring(cmd, k_old)
try:
    got = sa.destring(payload, k_new)
except Exception as e:
    got = None
    print("   (destring 抛异常:", e, ")")
print("用错 key 解出:", got)
assert got != cmd.encode(), "错 key 居然也解对了，L2 校验形同虚设"
assert sa.destring(payload, k_old) == cmd.encode()
print("OK 2: 错 key 解不开，对 key 才解得开")

# fid=8 同理
e_old = b"&;8;" + sa.enint(0, k_old) + b";" + sa.enint(0, k_old) + b";#;"
e_new = b"&;8;" + sa.enint(0, k_new) + b";" + sa.enint(0, k_new) + b";#;"
assert e_old != e_new, "fid=8 预编码必须也随 key 变"
print("OK 3: fid=8 用不同 key 编码结果不同 -> 不能启动时预编码成常量")

# ---- 3. 源码层面：run() 里不许再有局部 key 缓存 ----
# Engine 已于 2026-10-02 从 stw_ui.py 剥离到 stw_engine.py，源码扫描要跟着换文件
src = open(os.path.join(_ROOT, "stw_ui", "stw_engine.py"),
           encoding="utf-8").read()
run_src = src[src.index("    def run(self):"):]
bad = re.findall(r"^\s*key\s*=\s*self\.key\s*$", run_src, re.M)
assert not bad, f"Engine.run() 里又把 self.key 缓存成局部变量了：{bad}"
stale = []
for m in re.finditer(r"(build_battle_cmd|build_walk|destring|enint|enstring)"
                     r"\(([^()]*)\)", run_src):
    fn, args = m.group(1), m.group(2)
    # (?<!\.) 用来排除 self.key，只抓裸 key
    if re.search(r"(?<!\.)\bkey\b", args):
        stale.append((fn, args))
assert not stale, f"还有裸 key 的用法：{stale}"
assert "def send_end8" in run_src, "send_end8() 没了"
print("OK 4: Engine.run() 无局部 key 缓存，发包/解密全部走 self.key")

print("\nRESULT: PASS —— 账号校正后新 key 会立即生效")
