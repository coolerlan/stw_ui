"""
石器时代 2903 自走遇敌 / 快速遇敌 复现（STW0.30 行为对照）

对照 STW0.30.exe FUN_004048A0：
  1. 读游戏状态，只在地图上(state=9)才点击
  2. 在角色两侧交替取屏幕点，发鼠标点击让角色走过去
  3. 每轮 sleep(delay) —— 默认 20ms，设 0 即快速遇敌

【重要安全规则】
  当前机器上会有两个 sa_2903.exe：
    - 一个是 STW0.30.exe 启动的子进程  -> 禁止操作
    - 一个是用户自己手动开的          -> 只操作这个
  脚本用父进程名做硬过滤：父进程名含 "stw" 的一律跳过。
  只有 --pid 显式指定时才允许强制指定（会打印警告）。

依赖：仅标准库 + pywin32（win32gui / win32process / win32con）

用法：
  python auto_encounter.py --list                # 列出可用进程（含父进程名）
  python auto_encounter.py --dry-run             # 只打印状态，不点击
  python auto_encounter.py --delay 20            # 自走，每步 20ms
  python auto_encounter.py --delay 0             # 快速遇敌
  python auto_encounter.py --relog               # 只执行一次重登
  python auto_encounter.py --patches             # 打印 STW 加速补丁当前状态
  python auto_encounter.py --apply-patches       # 打上 STW 加速补丁
"""

import argparse
import ctypes
import sys
import time
from ctypes import wintypes

import win32con
import win32gui
import win32process

PROCESS_NAME = "sa_2903.exe"

# CE 实测的绝对地址（当时模块基址 0x400000）
IMAGE_BASE = 0x00400000

ABS = {
    "char_x": 0x02AD1AA4,  # 角色格子 X
    "char_y": 0x02AD1A9C,  # 角色格子 Y
    "map": 0x02AD1AA8,  # 地图号
    "state": 0x02B2694C,  # 9=地图上 10=战斗中
    "mouse_x": 0x02B00F28,  # 游戏内部鼠标 X
    "mouse_y": 0x02B00F2C,  # 游戏内部鼠标 Y
}

OFF = {k: v - IMAGE_BASE for k, v in ABS.items()}

STATE_LOGIN = 1
STATE_SERVER = 2
STATE_CHARSEL = 3
STATE_MAP = 9
STATE_BATTLE = 10

WM_MOUSEMOVE = 0x0200
WM_LBUTTONDOWN = 0x0201
WM_LBUTTONUP = 0x0202

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_psapi = ctypes.WinDLL("psapi", use_last_error=True)
_ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
_user32 = ctypes.WinDLL("user32", use_last_error=True)


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", ctypes.c_ulonglong),
        ("PebBaseAddress", ctypes.c_ulonglong),
        ("AffinityMask", ctypes.c_ulonglong),
        ("BasePriority", ctypes.c_ulonglong),
        ("UniqueProcessId", ctypes.c_ulonglong),
        ("InheritedFromUniqueProcessId", ctypes.c_ulonglong),
    ]


def _enum_pids():
    arr = (wintypes.DWORD * 8192)()
    needed = wintypes.DWORD()
    if not _psapi.EnumProcesses(ctypes.byref(arr), ctypes.sizeof(arr),
                                ctypes.byref(needed)):
        return []
    n = needed.value // ctypes.sizeof(wintypes.DWORD)
    return list(arr[:n])


def _pid_exe_name(pid):
    h = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                              False, pid)
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(1024)
        # GetModuleBaseNameW 在 psapi.dll，不在 kernel32
        if _psapi.GetModuleBaseNameW(h, None, buf, 1024):
            return buf.value
    finally:
        _kernel32.CloseHandle(h)
    return None


def _parent_pid(pid):
    h = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return None
    try:
        info = PROCESS_BASIC_INFORMATION()
        size = wintypes.ULONG()
        status = _ntdll.NtQueryInformationProcess(
            h, 0, ctypes.byref(info), ctypes.sizeof(info),
            ctypes.byref(size))
        if status != 0:
            return None
        return int(info.InheritedFromUniqueProcessId)
    finally:
        _kernel32.CloseHandle(h)


def _is_stw_child(pid):
    """父进程名含 stw 的就是 STW 开的，禁止操作。"""
    ppid = _parent_pid(pid)
    if not ppid:
        return False
    name = (_pid_exe_name(ppid) or "").lower()
    return "stw" in name


def list_clients():
    """列出所有 sa_2903.exe 及其父进程，标出可用/禁用。"""
    rows = []
    for pid in _enum_pids():
        if (_pid_exe_name(pid) or "").lower() != PROCESS_NAME.lower():
            continue
        ppid = _parent_pid(pid)
        # _pid_exe_name 可能返回 None（父进程已退出/权限不足），不能拿来格式化
        pname = (_pid_exe_name(ppid) if ppid else None) or "?"
        blocked = _is_stw_child(pid)
        rows.append((pid, ppid, pname, blocked))
    return rows


def find_game_pid():
    """挑一个可操作的客户端：排除 STW 子进程。"""
    rows = list_clients()
    usable = [r for r in rows if not r[3]]
    # 优先用启动时间更晚的那个没有意义，这里取第一个可用的
    return usable[0][0] if usable else None


def _module_base(pid):
    h = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                              False, pid)
    if not h:
        raise RuntimeError(f"打不开 PID={pid}")
    try:
        mods = (ctypes.c_void_p * 1024)()
        needed = wintypes.DWORD()
        _psapi.EnumProcessModules(h, ctypes.byref(mods), ctypes.sizeof(mods),
                                  ctypes.byref(needed))
        n = min(needed.value // ctypes.sizeof(ctypes.c_void_p), 1024)
        if n == 0:
            raise RuntimeError("EnumProcessModules 返回 0")
        info = MODULEINFO()
        # mods[0] 是 64 位指针值，直接传会被按 C int 截断 -> OverflowError，
        # 必须包成 c_void_p（对 32 位游戏同样适用）
        _psapi.GetModuleInformation(h, ctypes.c_void_p(mods[0]),
                                    ctypes.byref(info),
                                    ctypes.sizeof(info))
        return info.lpBaseOfDll
    finally:
        _kernel32.CloseHandle(h)


def find_main_window(pid):
    found = []

    def cb(hwnd, _):
        try:
            if not win32gui.IsWindowVisible(hwnd):
                return True
            _, wpid = win32process.GetWindowThreadProcessId(hwnd)
            if wpid != pid:
                return True
            if win32gui.GetWindowText(hwnd).strip():
                found.append(hwnd)
        except Exception:
            pass
        return True

    win32gui.EnumWindows(cb, None)
    return found[0] if found else None


class Game:
    def __init__(self, pid, writable=False):
        self.pid = pid
        self.base = _module_base(pid)
        self.hwnd = find_main_window(pid)
        if not self.hwnd:
            raise RuntimeError(f"PID={pid} 找不到游戏窗口")
        access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
        if writable:
            access |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION
        self._h = _kernel32.OpenProcess(access, False, pid)
        if not self._h:
            raise RuntimeError(f"OpenProcess 失败 PID={pid}")
        self._buf = ctypes.c_uint32()

    def addr(self, key):
        return self.base + OFF[key]

    def abs(self, absolute_addr):
        """把以 0x400000 为基址的绝对地址换算到当前进程的绝对地址。"""
        return self.base + (absolute_addr - IMAGE_BASE)

    def read_u32(self, key):
        ok = _kernel32.ReadProcessMemory(
            self._h, ctypes.c_void_p(self.addr(key)),
            ctypes.byref(self._buf), 4, None)
        if not ok:
            raise RuntimeError(f"读取失败 {key} @0x{self.addr(key):X}")
        return self._buf.value

    def snapshot(self):
        return {
            "x": self.read_u32("char_x"),
            "y": self.read_u32("char_y"),
            "map": self.read_u32("map"),
            "state": self.read_u32("state"),
        }

    def read_bytes(self, abs_addr, n):
        buf = ctypes.create_string_buffer(n)
        read = ctypes.c_size_t()
        ok = _kernel32.ReadProcessMemory(
            self._h, ctypes.c_void_p(abs_addr), buf, n, ctypes.byref(read))
        if not ok:
            raise RuntimeError(f"读取失败 @0x{abs_addr:X}")
        return buf.raw[:read.value]

    def write_bytes(self, abs_addr, data: bytes):
        written = ctypes.c_size_t()
        old = wintypes.DWORD()
        _kernel32.VirtualProtectEx(self._h, ctypes.c_void_p(abs_addr),
                                   len(data), 0x40, ctypes.byref(old))
        ok = _kernel32.WriteProcessMemory(
            self._h, ctypes.c_void_p(abs_addr), data, len(data),
            ctypes.byref(written))
        _kernel32.VirtualProtectEx(self._h, ctypes.c_void_p(abs_addr),
                                   len(data), old, ctypes.byref(old))
        if not ok or written.value != len(data):
            raise RuntimeError(f"写入失败 @0x{abs_addr:X}")
        return True

    def client_size(self):
        left, top, right, bottom = win32gui.GetClientRect(self.hwnd)
        return right - left, bottom - top

    def click(self, x, y, post=False):
        """点击客户区坐标。默认 SendMessage（已验证可用）。"""
        lparam = (y << 16) | (x & 0xFFFF)
        if post:
            win32gui.PostMessage(self.hwnd, WM_MOUSEMOVE, 0, lparam)
            win32gui.PostMessage(self.hwnd, WM_LBUTTONDOWN,
                                 win32con.MK_LBUTTON, lparam)
            win32gui.PostMessage(self.hwnd, WM_LBUTTONUP, 0, lparam)
        else:
            win32gui.SendMessage(self.hwnd, WM_MOUSEMOVE, 0, lparam)
            win32gui.SendMessage(self.hwnd, WM_LBUTTONDOWN,
                                 win32con.MK_LBUTTON, lparam)
            win32gui.SendMessage(self.hwnd, WM_LBUTTONUP, 0, lparam)

    def press_escape(self):
        """硬件 ESC。PostMessage 的按键消息打不开这个客户端的菜单。"""
        current = _kernel32.GetCurrentThreadId()
        target = _user32.GetWindowThreadProcessId(self.hwnd, None)
        _user32.AttachThreadInput(current, target, True)
        try:
            _user32.SetForegroundWindow(self.hwnd)
            _user32.BringWindowToTop(self.hwnd)
            time.sleep(0.1)
            _user32.keybd_event(win32con.VK_ESCAPE, 0, 0, 0)
            time.sleep(0.05)
            _user32.keybd_event(win32con.VK_ESCAPE, 0,
                                win32con.KEYEVENTF_KEYUP, 0)
            time.sleep(0.35)
        finally:
            _user32.AttachThreadInput(current, target, False)

    def relog(self):
        """登出再登入（已验证坐标）。"""
        hwnd = self.hwnd
        self.press_escape()
        self.click(83, 63)
        time.sleep(0.25)
        self.click(83, 63)
        time.sleep(0.6)
        self.click(591, 192)
        time.sleep(1.0)
        steps = ((320, 265, 1.2),   # OK
                 (250, 235, 2.5),   # 4 服
                 (330, 305, 2.0),   # 线路
                 (100, 335, 2.2))   # 角色登入
        for x, y, delay in steps:
            self.click(x, y)
            time.sleep(delay)
        return self.snapshot()

    def close(self):
        try:
            _kernel32.CloseHandle(self._h)
        except Exception:
            pass


# ---- STW 加速补丁 ----
#
# 这些不是猜的：STW0.30.exe 的 0x46F0~0x4DF0 内嵌了一张补丁表，
# 每条记录形如  push 长度 / lea 缓冲 / push 地址 / 写字节 / call 写内存。
# 下表就是从那张表里逐条还原出来的，字节值与 STW 完全一致。
#
# 语义：
#   7x xx -> 90 90    : 条件跳转永不生效（跳过等待/限速）
#   0F 8x -> 90 E9    : je/jne/jae 改成 jmp，强制走分支（跳过界面等待）
#   74/EB -> EB       : 强制跳转
#   0x43E664 与 0x45499F 针对同一个计数器 0x02AB0880（一个 add 一个 dec），
#                       必须成对 NOP，只 NOP 一个会让计数器失控 -> 客户端卡死。

PATCHES = {
    "move": (
        (0x402814, "7C2B", "9090", "移动开关 jl 失效"),
        (0x4323DA, "7D11", "9090", "移动判定 jge 失效"),
        (0x45499F, "FF0D8008AB02", "909090909090", "计数器 dec 去掉"),
        (0x454993, "00", "01", "等待标志 0->1"),
        (0x43E664, "01058008AB02", "909090909090", "计数器 add 去掉"),
        (0x406146, "7D11", "9090", "行走循环1 jge 失效"),
        (0x406157, "EB10", "9090", "行走循环跳转失效"),
        (0x40617B, "7E2E", "9090", "行走判定 jle 失效"),
        (0x40657D, "7E7C", "9090", "行走判定 jle 失效"),
        (0x406ECC, "7C14", "9090", "行走判定 jl 失效"),
    ),
    "ui": (
        (0x426689, "7425", "EB25", "界面等待 je->jmp"),
        (0x429625, "722B", "9090", "界面等待 jb 失效"),
        (0x4011B2, "0F84", "90E9", "流程 je->jmp"),
        (0x40A6A0, "0F84", "90E9", "流程 je->jmp"),
        (0x44B4E8, "0F84", "90E9", "流程 je->jmp"),
        (0x410133, "0F84", "90E9", "流程 je->jmp"),
        (0x40FE4B, "0F83", "90E9", "流程 jae->jmp"),
        (0x410127, "0F85", "90E9", "流程 jne->jmp"),
        (0x44D7FA, "0F85", "90E9", "流程 jne->jmp"),
        (0x40B786, "A168", "EB0F", "界面取数据跳过"),
        (0x4697F0, "01", "05", "界面参数 1->5"),
    ),
}

PATCH_GROUPS = ("move", "ui")


def _iter_patches(group: str):
    for addr, orig, patched, desc in PATCHES[group]:
        yield addr, bytes.fromhex(orig), bytes.fromhex(patched), desc


def show_patches(game: Game):
    print(f"基址=0x{game.base:X}")
    for group in PATCH_GROUPS:
        print(f" [{group}]")
        for addr, orig, patched, desc in _iter_patches(group):
            cur = game.read_bytes(game.abs(addr), len(orig))
            if cur == orig:
                st = "原始"
            elif cur == patched:
                st = "已打补丁"
            else:
                st = "其它"
            print(f"  0x{addr:06X} {desc:<18} 当前={cur.hex().upper():<12} {st}")


def apply_patches(game: Game, group: str = "move"):
    for addr, orig, patched, desc in _iter_patches(group):
        a = game.abs(addr)
        cur = game.read_bytes(a, len(orig))
        if cur == patched:
            print(f"  0x{addr:06X} {desc} 已是补丁状态")
            continue
        if cur != orig:
            print(f"  0x{addr:06X} {desc} 当前不是原始值({cur.hex().upper()})，跳过")
            continue
        game.write_bytes(a, patched)
        print(f"  0x{addr:06X} {desc} {cur.hex().upper()} -> {patched.hex().upper()}")


def restore_patches(game: Game):
    for group in PATCH_GROUPS:
        for addr, orig, patched, desc in _iter_patches(group):
            a = game.abs(addr)
            cur = game.read_bytes(a, len(orig))
            if cur == orig:
                continue
            game.write_bytes(a, orig)
            print(f"  0x{addr:06X} {desc} 已还原")


def walk_points(game):
    """
    STW 巡逻用的两个点是 (0x120,0x108) 和 (0x160,0xD8)，
    即 640x480 客户区中心 (320,240) 各偏移 (32,24)。
    这里按客户区尺寸换算，窗口大小变了也能用。
    """
    w, h = game.client_size()
    cx, cy = w // 2, h // 2
    dx = max(8, int(w * 32 / 640))
    dy = max(6, int(h * 24 / 480))
    return [(cx - dx, cy + dy), (cx + dx, cy - dy)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--delay", type=int, default=20,
                    help="每次点击后等待毫秒，0 = 快速遇敌")
    ap.add_argument("--dry-run", action="store_true", help="只打印状态，不点击")
    ap.add_argument("--pid", type=int, default=0, help="指定 PID（会跳过 STW 过滤检查）")
    ap.add_argument("--list", action="store_true", help="只列出进程")
    ap.add_argument("--relog", action="store_true", help="执行一次重登后退出")
    ap.add_argument("--patches", action="store_true", help="打印补丁状态")
    ap.add_argument("--apply-patches", nargs="?", const="move", default=None,
                    choices=PATCH_GROUPS + ("all",),
                    help="打上加速补丁: move / ui / all")
    ap.add_argument("--restore", action="store_true", help="还原全部补丁到原始字节")
    ap.add_argument("--seconds", type=float, default=0, help="运行时长上限，0=不限")
    ap.add_argument("--max-clicks", type=int, default=0, help="点击次数上限，0=不限")
    ap.add_argument("--post", action="store_true", help="用 PostMessage 代替 SendMessage")
    ap.add_argument("--trace", action="store_true", help="打印每次坐标变化及耗时")
    args = ap.parse_args()

    if args.list:
        for pid, ppid, pname, blocked in list_clients():
            tag = "STW 子进程 [禁止操作]" if blocked else "可用 [你的客户端]"
            print(f"PID={pid:<7} 父={ppid:<7} {pname:<16} {tag}")
        return 0

    if args.pid:
        if _is_stw_child(args.pid):
            print(f"!! PID={args.pid} 是 STW0.30.exe 的子进程，拒绝操作。")
            return 2
        pid = args.pid
    else:
        pid = find_game_pid()
        if not pid:
            print(f"没找到可操作的 {PROCESS_NAME}（全部是 STW 子进程或没运行）")
            return 1

    writable = bool(args.apply_patches) or args.restore
    game = Game(pid, writable=writable)

    if args.patches:
        show_patches(game)
        game.close()
        return 0

    if args.restore:
        print("还原补丁:")
        restore_patches(game)
        game.close()
        return 0

    if args.apply_patches:
        groups = PATCH_GROUPS if args.apply_patches == "all" else (args.apply_patches,)
        for g in groups:
            print(f"打补丁 [{g}]:")
            apply_patches(game, g)
        game.close()
        return 0

    if args.relog:
        print(f"重登 PID={pid} ...")
        before = game.snapshot()
        print("  重登前:", before)
        after = game.relog()
        print("  重登后:", after)
        game.close()
        return 0

    points = walk_points(game)
    w, h = game.client_size()

    print(f"PID={game.pid} hwnd={game.hwnd} 基址=0x{game.base:X} 客户区={w}x{h}")
    print(f"点击点={points} 延迟={args.delay}ms"
          + ("  [DRY RUN 不点击]" if args.dry_run else ""))
    print("Ctrl+C 停止\n")

    idx = 0
    last_print = 0.0
    clicks = 0
    start = time.time()
    last_pos = None
    last_move = start
    try:
        while True:
            st = game.snapshot()
            now = time.time()

            if args.trace:
                pos = (st["x"], st["y"], st["state"])
                if pos != last_pos:
                    if last_pos is not None:
                        print(f"    +{(now - last_move) * 1000:6.0f}ms  "
                              f"({last_pos[0]},{last_pos[1]}) -> "
                              f"({st['x']},{st['y']}) state={st['state']}")
                    last_pos = pos
                    last_move = now

            if now - last_print >= 1.0:
                tag = {STATE_MAP: "地图", STATE_BATTLE: "战斗",
                       STATE_LOGIN: "登录", STATE_SERVER: "选服",
                       STATE_CHARSEL: "选角色"}.get(
                    st["state"], f"state={st['state']}")
                print(f"[{time.strftime('%H:%M:%S')}] {tag} "
                      f"地图={st['map']} 坐标=({st['x']},{st['y']}) "
                      f"已点击={clicks}")
                last_print = now

            if st["state"] == STATE_MAP and not args.dry_run:
                x, y = points[idx % len(points)]
                game.click(x, y, post=args.post)
                idx += 1
                clicks += 1

            if args.seconds and now - start >= args.seconds:
                print(f"到达 {args.seconds}s 上限，停止")
                break
            if args.max_clicks and clicks >= args.max_clicks:
                print(f"到达 {args.max_clicks} 次点击，停止")
                break

            time.sleep(args.delay / 1000.0)

    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        game.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
