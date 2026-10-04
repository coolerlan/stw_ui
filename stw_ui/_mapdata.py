"""Stoneage MAP 文件解析 + 可走性判定。

文件布局（实测 32006.MAP：60x60，7208 = 8 + 60*60*2 字节）：
    int32 width
    int32 height
    plane1[height][width]   uint8   地形/阻挡层
    plane2[height][width]   uint8   附属层（叠加/事件层）

取值统计（32006.MAP）：
    plane1: 112 x1984   165 x1526   166 x71   167 x19
    plane2: 113 x1984   165 x1194   164 x330  167 x71   166 x21

语义：
    plane1 == 112            -> 墙 / 不可走（与 plane2==113 成对出现，数量完全一致）
    plane1 == 165            -> 普通地面
        plane2 == 165        -> 可遇敌地面
        plane2 == 164        -> 地面但不可遇敌（村镇/建筑内，走上去不会遇敌）
    plane1 in (166, 167)     -> 特殊格（楼梯 / 传送 / 事件点）
        (166,167) x71  (167,166) x~20

踩上去的后果：
    走一步到 166/167 会触发服务器广播 fid=43（遇敌动画/传送动画），
    STW 快速遇敌时踩到这些格子会导致位置乱跳甚至掉线，必须避开。
"""
import os
import struct

MAP_DIR = r"D:\zcgd2.5(new)\SACH-MX0.30\MAP"

BLOCK = 112        # plane1 墙
GROUND = 165       # plane1 普通地面
SPECIAL = (166, 167)   # plane1 特殊格（楼梯/传送/事件）
NO_ENCOUNTER = 164     # plane2 该值 = 地面但不会遇敌

_cache = {}


class MapInfo:
    def __init__(self, map_id: int, w: int, h: int, p1: bytes, p2: bytes):
        self.map_id = map_id
        self.w, self.h = w, h
        self.p1, self.p2 = p1, p2

    def inside(self, x: int, y: int) -> bool:
        return 0 <= x < self.w and 0 <= y < self.h

    def at(self, x: int, y: int):
        """返回 (plane1, plane2)；越界返回 None。"""
        if not self.inside(x, y):
            return None
        i = y * self.w + x
        return self.p1[i], self.p2[i]

    # ---- 判定 ----
    def is_blocked(self, x: int, y: int) -> bool:
        v = self.at(x, y)
        return v is None or v[0] == BLOCK

    def is_special(self, x: int, y: int) -> bool:
        v = self.at(x, y)
        return v is None or v[0] in SPECIAL

    def is_ground(self, x: int, y: int) -> bool:
        """普通地面（可站），不含特殊格、不含墙。"""
        v = self.at(x, y)
        return v is not None and v[0] == GROUND

    def can_encounter(self, x: int, y: int) -> bool:
        """普通地面 且 plane2 != 164（164 = 村镇/建筑内，不会遇敌）。"""
        v = self.at(x, y)
        return v is not None and v[0] == GROUND and v[1] != NO_ENCOUNTER

    def safe(self, x: int, y: int) -> bool:
        """快速遇敌意义上的"安全落点"：普通地面、非特殊格、非墙。"""
        return self.is_ground(x, y)

    def describe(self, x: int, y: int) -> str:
        v = self.at(x, y)
        if v is None:
            return f"({x},{y}) 越界"
        a, b = v
        if a == BLOCK:
            t = "墙/不可走"
        elif a in SPECIAL:
            t = "特殊格(楼梯/传送/事件)"
        elif b == NO_ENCOUNTER:
            t = "地面(不可遇敌)"
        else:
            t = "地面(可遇敌)"
        return f"({x},{y}) -> ({a}, {b})  {t}"


def load(map_id: int, map_dir: str = MAP_DIR) -> MapInfo:
    """按地图号加载 MAP，带缓存。找不到返回 None。"""
    if map_id in _cache:
        return _cache[map_id]
    for name in (f"{map_id}.MAP", f"{map_id}.map"):
        p = os.path.join(map_dir, name)
        if os.path.isfile(p):
            d = open(p, "rb").read()
            w, h = struct.unpack("<ii", d[:8])
            n = w * h
            if len(d) < 8 + n * 2:
                raise ValueError(f"{name} 尺寸不符: {len(d)} < {8 + n * 2}")
            mi = MapInfo(map_id, w, h, d[8:8 + n], d[8 + n:8 + 2 * n])
            _cache[map_id] = mi
            return mi
    _cache[map_id] = None
    return None


# 8 方向，与协议里的字母一致
DIRS = {"a": (0, -1), "b": (1, -1), "c": (1, 0), "d": (1, 1),
        "e": (0, 1), "f": (-1, 1), "g": (-1, 0), "h": (-1, -1)}
OPP = {"a": "e", "b": "f", "c": "g", "d": "h",
       "e": "a", "f": "b", "g": "c", "h": "d"}


def pick_axis(mi: MapInfo, x: int, y: int, prefer: str = "c"):
    """在 (x,y) 处挑一条"来回摆动都安全"的轴。

    服务器只执行路径第一步就遇敌，所以落点 = 起点 + DIRS[第一步]。
    要让 ±1 漂移永不踩到墙/特殊格，就要求这条轴的正反两个邻格都是普通地面。

    两级筛选（重要）：
      1. 两侧都能遇敌（plane2 != 164）——最理想，漂移不影响遇敌
      2. 两侧都只是普通地面（可能有一侧是 164 不可遇敌区）——退而求其次

    (10,8) 实测是 (165,164)：能站但不会遇敌，漂过去遇敌就停了，
    所以必须优先用第 1 级筛选。

    返回 (正向字母, 反向字母)；两级都不满足返回 None。
    """
    if mi is None:
        return (prefer, OPP[prefer])
    order = [prefer, OPP[prefer]]
    for d in "abcdefgh":
        if d not in order:
            order.append(d)
    for test in (lambda m, px, py: m.can_encounter(px, py),
                 lambda m, px, py: m.safe(px, py)):
        for d in order:
            dx, dy = DIRS[d]
            if test(mi, x + dx, y + dy) and test(mi, x - dx, y - dy):
                return (d, OPP[d])
    return None


if __name__ == "__main__":
    import sys
    mid = int(sys.argv[1]) if len(sys.argv) > 1 else 32006
    mi = load(mid)
    print(f"map {mid}: {mi.w}x{mi.h}")
    args = sys.argv[2:]
    if args:
        for i in range(0, len(args), 2):
            print(mi.describe(int(args[i]), int(args[i + 1])))
    else:
        for y in range(6, 11):
            print(" ".join(f"{mi.at(x, y)[0]:3d}" for x in range(5, 12)))
