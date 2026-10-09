"""进程内存扫描：在登录界面里找玩家输入的账号串。

游戏主窗口 class 是 `ＳｔｏｎｅＡｇｅ`，纯自绘、没有任何 Win32 子控件
（EnumChildWindows 为空），所以拿不到 WM_GETTEXT，只能扫内存。

用法：
    python _scan_mem.py <pid> <关键字>        # 精确找某个串
    python _scan_mem.py <pid> --candidates    # 列出所有像账号的候选串
"""
import ctypes
import ctypes.wintypes as wt
import re
import sys
import time

k32 = ctypes.windll.kernel32
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

PROTECT_OK = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}  # 可读的几档


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


class Mem:
    def __init__(self, pid: int):
        self.h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                 False, pid)
        if not self.h:
            raise RuntimeError(f"OpenProcess({pid}) 失败")

    def close(self):
        k32.CloseHandle(self.h)

    def regions(self):
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        sz = ctypes.sizeof(mbi)
        while addr < 0x7FFF0000:
            if not k32.VirtualQueryEx(self.h, ctypes.c_void_p(addr),
                                      ctypes.byref(mbi), sz):
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize
            if (mbi.State == MEM_COMMIT and mbi.Protect in PROTECT_OK
                    and not (mbi.Protect & PAGE_GUARD)):
                yield base, size, mbi.Type
            addr = base + size

    def read(self, addr, n):
        buf = ctypes.create_string_buffer(n)
        rd = ctypes.c_size_t()
        ok = k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf, n,
                                   ctypes.byref(rd))
        if not ok:
            return b""
        return buf.raw[:rd.value]


CAND = re.compile(rb"[A-Za-z0-9_]{3,16}")


MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000

# 账号 + "bing" 就是 L2 密钥，游戏会把它拼好放在堆里（实测 0x2f3be48:
# b'<账号>bing\x00...'）。只认 NUL 结尾、长度 3~16 的账号部分。
KEY_PAT = re.compile(rb"(?<![A-Za-z0-9_])([A-Za-z0-9_]{3,16})bing\x00")


def main_module_range(pid: int):
    """主模块（sa_2903.exe）的 [基址, 结束)。密钥就存在它自己的映像段里。"""
    psapi = ctypes.windll.psapi
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return 0, 0
    try:
        mod = ctypes.c_void_p()
        needed = wt.DWORD()
        psapi.EnumProcessModules(h, ctypes.byref(mod), ctypes.sizeof(mod),
                                 ctypes.byref(needed))
        if not mod:
            return 0, 0

        class MODULEINFO(ctypes.Structure):
            _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                        ("SizeOfImage", wt.DWORD),
                        ("EntryPoint", ctypes.c_void_p)]
        mi = MODULEINFO()
        psapi.GetModuleInformation(h, mod, ctypes.byref(mi), ctypes.sizeof(mi))
        return (mi.lpBaseOfDll or 0), (mi.lpBaseOfDll or 0) + mi.SizeOfImage
    finally:
        k32.CloseHandle(h)


def find_keys(m: Mem, lo: int = 0, hi: int = 0, limit=40):
    """扫出形如 `<账号>bing\\0` 的 L2 密钥，返回账号列表（按可信度排序）。

    必须限定在主模块范围内扫：.NET / 系统 DLL 里有 "StopSubscribing"、
    "…Probing" 这类以 bing 结尾的英文单词，会造成一堆假阳性。
    实测 <账号>bing 位于主模块自己的 MEM_IMAGE 段（0x2f3be48）。
    """
    hits = {}
    for base, size, typ in m.regions():
        if hi and not (lo <= base < hi):
            continue
        if size > 64 << 20:
            continue
        data = m.read(base, size)
        if not data:
            continue
        for mo in KEY_PAT.finditer(data):
            acct = mo.group(1).decode()
            hits.setdefault(acct, hex(base + mo.start()))
            if len(hits) >= limit:
                break
        if len(hits) >= limit:
            break

    def score(a):
        # 全小写/纯数字更像账号；其次长度越长越像（避开 f1ju 这类碎片）
        return (0 if (a.islower() or a.isdigit()) else 1, -len(a), a)

    return sorted(hits, key=score), hits


def find_exact(m: Mem, needle: bytes, limit=40):
    """精确匹配（ASCII 与 UTF-16LE 各找一遍）。"""
    hits = []
    u16 = needle.decode().encode("utf-16-le")
    for base, size, typ in m.regions():
        if size > 64 << 20:          # 跳过超大影像段
            continue
        data = m.read(base, size)
        if not data:
            continue
        for pat, tag in ((needle, "ascii"), (u16, "utf16")):
            start = 0
            while len(hits) < limit:
                i = data.find(pat, start)
                if i < 0:
                    break
                hits.append((hex(base + i), tag, data[i:i + 40]))
                start = i + 1
            if len(hits) >= limit:
                break
        if len(hits) >= limit:
            break
    return hits


def find_candidates(m: Mem, min_len=4, limit=60):
    """扫出所有像账号的 NUL 结尾 ASCII 串（登录框里刚打进去的那种）。"""
    out = {}
    for base, size, typ in m.regions():
        if size > 32 << 20:
            continue
        data = m.read(base, size)
        if not data:
            continue
        for mo in CAND.finditer(data):
            s = mo.group()
            if len(s) < min_len:
                continue
            e = mo.end()
            if e < len(data) and data[e] != 0:
                continue                       # 必须 NUL 结尾才像输入框内容
            out.setdefault(s.decode(), hex(base + mo.start()))
            if len(out) >= limit:
                return out
    return out


if __name__ == "__main__":
    pid = int(sys.argv[1])
    m = Mem(pid)
    t0 = time.time()
    if len(sys.argv) > 2 and sys.argv[2] == "--keys":
        lo, hi = main_module_range(pid)
        print(f"主模块 {hex(lo)} ~ {hex(hi)}（{hi-lo} 字节）")
        accs, hits = find_keys(m, lo, hi)
        print(f"L2 key 候选 {len(accs)} 个（用时 {time.time()-t0:.1f}s）")
        for a in accs:
            print(f"   {hits[a]}  {a}   -> key={a}bing")
    elif len(sys.argv) > 2 and sys.argv[2] == "--candidates":
        res = find_candidates(m)
        print(f"候选账号串 {len(res)} 个（用时 {time.time()-t0:.1f}s）")
        for k, v in res.items():
            print(f"   {v}  {k}")
    else:
        needle = sys.argv[2].encode() if len(sys.argv) > 2 else b"youraccount"
        hits = find_exact(m, needle)
        print(f"精确匹配 {needle!r}: {len(hits)} 处（用时 {time.time()-t0:.1f}s）")
        for a, tag, ctx in hits:
            print(f"   {a} [{tag}] {ctx!r}")
    m.close()
