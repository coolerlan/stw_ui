# stw_ui

**致敬 stw0.30.exe**

用于启动 `sa_2903.exe`，自动捕捉野生**满档巴朵兰恩**。

这版 py 主要实现了一个能**逃跑、上毒、战后补血（吃道具 2-15 补气）**的收发包状态机。

---

## 使用前配置

| 项目 | 要求 |
| --- | --- |
| 宠物栏 | **骑宠排第一**，后面空四个位置 |
| 背包 | **贝壳放第一格**，**2-15 格放气瓶** |
| 装备 | 毒枪 + 滋润 3 铠 |
| 位置 | 手动走到**水坝**地图 |

点击「开始」后：自动快速遇敌 → 按巴朵兰恩的等级筛选指定 `maxhp` 上毒 →
匹配指定毒伤抓宠 → 战斗结束后判断是否满档。

## 快速开始

```bat
:: 1. 建虚拟环境 + 装依赖
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt

:: 2. 启动（无黑窗）
双击 启动控制台.vbs
:: 或者要看输出的调试版
启动控制台.bat
```


## 目录结构

```text
sqsd_py/
│
├── 启动控制台.vbs
│
├── stw_ui/
│   ├── __init__.py                 （新增：包入口，只负责把包目录挂进 sys.path）
│   │
│   ├── stw_battle.py               战斗中"做什么"：BC/BA/BH 解析 → 产出 Command
│   ├── stw_engine.py               "怎么发"：主循环、发包、战后恢复、抓宠统计
│   ├── stw_config.py               全局配置 + 路径注册（被最先导入）
│   ├── stw_pet.py                  宠物面板解析 / 满档判定 / 抓宠规则
│   ├── stw_process.py              拉起游戏、加速补丁、心跳
│   ├── stw_protocol.py             L2 报文解析与构造（无状态纯函数）
│   ├── stw_ui.py                   Tkinter 控制台界面
│   ├── stw_watch.py                游戏状态监听 → UI 事件队列
│   │
│   ├── fast_encounter.py           快速遇敌（fid=1 走位）
│   ├── auto_encounter.py           进程/内存扫描、账号与 L2 key 识别
│   ├── _frida_agent.py             frida 注入脚本
│   └── _mapdata.py                 地图数据
│
├── tests/
│   ├── test_battle.py
│   ├── test_catch_stat.py
│   ├── test_pet.py
│   ├── test_protocol.py
│   ├── test_recovery.py
│   │
│   ├── _test_accept.py
│   ├── _test_ba.py
│   ├── _test_catch.py
│   ├── _test_drop.py
│   ├── _test_encounter.py
│   ├── _test_hook_separation.py
│   ├── _test_keyswitch.py
│   ├── _test_pet_panel.py
│   ├── _test_poison.py
│   ├── _test_slot.py
│   └── _verify_attack.py
│
├── data/
│   └── 巴朵兰恩_95-105_MAXHP_猛毒DeltaHP.json
│
├── tests/data/
│   └── _test_pet_log.jsonl
│
├── README.md
├── requirements.txt
└── .gitignore
```

### `data/` —— 猛毒毒伤权威表

`巴朵兰恩_95-105_MAXHP_猛毒DeltaHP.json` 是**上毒判定用的权威数据**：
Lv95~105 每级的满档 `max_hp` 候选值、以及该级的猛毒掉血值。

```text
95:118  96:120  97:121  98:122  99:123  100:125
101:126 102:127 103:128 104:129 105:131
```

口径来自服务端 `magic.txt`：

```
K      = (等级-1) * 4 + 27
掉血    = (K * (V+S+T+D) // 100 - 20) // 4
```

满档原始四维和恒为 `25+39+22+27+10 = 123`，所以**每个等级只有一个掉血值**。

> ⚠ 别把面板数值代进这个公式：面板 `hp` 约为「体」的 4 倍，
> 面板攻/防/敏（`grow_stats`，带交叉项）也不是公式里的原始四维。
> 用面板值会算出 145/146 这种与实测表不符的数。

这份表同时是 `stw_pet.CATCH_SAMPLE_TEXT` 的口径来源
（界面「载入示例」按钮写进规则库的就是那张表）。


### 分层约束

```
stw_ui.py  →  stw_engine.py  →  stw_battle.py
                             ↘  stw_protocol.py / stw_pet.py
```

严格单向：`stw_engine.py` **不许** import `stw_ui`、也**不许** import `tkinter`。
`stw_battle.py` 只回答"这回合做什么"（返回 `Command`），"怎么发出去"归 Engine。

## 跑测试

```bat
cd tests
python test_protocol.py
python test_pet.py
python test_battle.py
python test_catch_stat.py
python test_recovery.py
```

几点说明：

- 每个测试文件都从 `__file__` 推导仓库根和包目录，**不依赖写死的绝对路径**，
  换台机器 clone 下来就能跑。
- `_test_accept.py` / `_test_encounter.py` / `_verify_attack.py` 需要**游戏正在运行**
  （会去枚举 `sa_2903.exe` 进程），没开游戏时会报"打不开 PID"，属正常。
- `_test_ba.py` 回放 `stw_ui_log.jsonl`（运行产物，被 gitignore），
  本地没有时会打印 `SKIP` 并正常退出，不算失败。
- `_test_poison.py` 的 P10 用例目前是红的：UI 里 `v_pverify` 默认是 `strict`，
  而 `CATCH_CFG_DEFAULTS["poison_verify"]` 是 `log`，两者不一致，待定。

## 运行产物（都在仓库根，已 gitignore）

| 文件 | 内容 |
| --- | --- |
| `stw_ui_log.jsonl` | 抓包帧日志（`dir` / `fid` / 首字段） |
| `stw_console_log.txt` | 界面上所有输出 |
| `stw_heartbeat.txt` | 每秒一行，进程硬崩也能看出死在哪一步 |
| `stw_crash.txt` | faulthandler：段错误 / 访问违例时的 Python 栈 |
| `catch_rules.json` | 抓宠规则库（本机配置） |

## 已知瑕疵

- **战后地图切换**还有问题。
- **角色显示**还有问题。

---

仅供学习研究网络协议与自动化，请遵守所在服务器规则，后果自负。
