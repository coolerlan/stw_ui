#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
石器时代野外宠物满档反推工具

按服务端源码：
1) enemybase 四围各自先 RAND(0,4)-2
2) 再随机分配 10 点到 VITAL/STR/TOUGH/DEX
3) CHAR_* = ((level-1)*lvup + initnum) * 最终点数
4) MAXHP / 攻 / 防 / 敏按 CHAR_complianceParameter() 计算

默认参数为巴朵兰恩：
enemybase = 23,37,20,25
lvup=4, initnum=27
"""

from itertools import product
import argparse

BASE = (23, 37, 20, 25)
NAMES = ("体", "攻", "防", "敏")


def calc(level, pre10, alloc10, lvup=4, initnum=27):
    """给定 ±2 后四围和 10 点分配，计算游戏显示的 HP/攻/防/敏。"""
    k = (level - 1) * lvup + initnum
    pts = tuple(pre10[i] + alloc10[i] for i in range(4))
    V, S, T, D = (k * x for x in pts)

    maxhp = int((V * 4 + S + T + D) * 0.01)

    # char.c -> CHAR_complianceParameter()
    attack = int(
        S * 0.01 +
        T * 0.01 * 0.1 +
        V * 0.01 * 0.1 +
        D * 0.01 * 0.05
    )
    defence = int(
        T * 0.01 +
        S * 0.01 * 0.1 +
        V * 0.01 * 0.1 +
        D * 0.01 * 0.05
    )
    dex = int(D * 0.01)

    return (maxhp, attack, defence, dex), pts, k


def allocations(total=10):
    for v in range(total + 1):
        for s in range(total - v + 1):
            for t in range(total - v - s + 1):
                d = total - v - s - t
                yield (v, s, t, d)


def reverse(level, maxhp, attack, defence, dex, base=BASE):
    """穷举源码允许的 ±2 和 10 点随机分布，找出所有精确匹配。"""
    target = (maxhp, attack, defence, dex)
    matches = []

    ranges = [range(x - 2, x + 3) for x in base]
    for pre10 in product(*ranges):
        for alloc in allocations(10):
            stats, finalpts, k = calc(level, pre10, alloc)
            if stats == target:
                matches.append((pre10, alloc, finalpts, k))
    return matches


def main():
    p = argparse.ArgumentParser(description="野外宠物满档反推")
    p.add_argument("level", type=int)
    p.add_argument("maxhp", type=int)
    p.add_argument("attack", type=int)
    p.add_argument("defence", type=int)
    p.add_argument("dex", type=int)
    args = p.parse_args()

    matches = reverse(args.level, args.maxhp, args.attack, args.defence, args.dex)

    print(f"输入：Lv{args.level} HP={args.maxhp} 攻={args.attack} 防={args.defence} 敏={args.dex}")
    print(f"enemybase：体攻防敏 = {BASE}")
    print(f"匹配方案数：{len(matches)}")

    if not matches:
        print("结论：按当前源码参数，没有精确匹配的野怪生成方案。")
        return

    full_pre10 = tuple(x + 2 for x in BASE)
    all_full = all(m[0] == full_pre10 for m in matches)

    for i, (pre10, alloc, finalpts, k) in enumerate(matches, 1):
        print(f"\n方案 {i}")
        print(f"  等级系数 K = {k}")
        print(f"  ±2随机后：{pre10}")
        print(f"  10点分布：体+{alloc[0]} 攻+{alloc[1]} 防+{alloc[2]} 敏+{alloc[3]}")
        print(f"  最终点数：{finalpts}")
        print(f"  是否四项均为 +2 最高随机：{'是' if pre10 == full_pre10 else '否'}")

    if len(matches) == 1 and all_full:
        print("\n结论：满档。并且该组显示属性能唯一反推出四项 ±2 随机全部取最高值。")
    elif all_full:
        print("\n结论：满档。所有可能解的四项 ±2 随机都取最高值。")
    else:
        print("\n结论：不能仅凭这组属性判定为满档，因为存在非满随机方案也能得到相同显示属性。")


if __name__ == "__main__":
    main()
