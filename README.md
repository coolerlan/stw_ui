# stw_ui

**致敬 stw0.30.exe**

用于启动 `sa_2903.exe`，自动捕捉野生**满档巴朵兰恩**。

这版 py 主要实现了一个能**逃跑、上毒、战后补血（吃道具 2-15 补气）**的收发包状态机。

---

## 使用前配置

| 项目 | 要求 |
| --- | --- |
| 宠物栏 | **骑宠排第一**，后面空四个位置 |
| 背包 | **上岛贝壳放第一格**，**2-15 格放气瓶** |
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

需要本机已安装游戏（`stw_config.py` 里的 `GAME_EXE` / `GAME_CWD` 指向你的安装目录），
且 L2 编解码模块 `dumpcap_realtime_stream_vNN_encounter_rescue.py` 可用
（默认在 `~/Downloads/` 下找版本号最高的那份，也可用环境变量 `SA_CODEC` 指定）。

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
├── tests/data/
│   └── _test_pet_log.jsonl
│
├── README.md
├── requirements.txt
└── .gitignore
```

> `auto_encounter.py` / `_frida_agent.py` / `_mapdata.py` 不在你列的那份清单里，
> 但 `stw_engine.py` 和 `stw_process.py` 在 import 阶段就要用它们，缺了控制台直接起不来，
> 所以一起收进了 `stw_ui/`。

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
