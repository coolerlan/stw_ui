"""STW 0.30 控制台 —— 石器时代 sa_2903.exe 自动抓宠（满档巴朵兰恩）。

包内各模块之间用的是**扁平绝对导入**（`from stw_config import ...`），
所以这里唯一必须做的事就是把本包目录挂进 sys.path，
否则 `import stw_ui.stw_engine` 会在 import 阶段找不到 stw_config。

⚠ 这里刻意不 import stw_engine / stw_ui：它们会拉起 frida / tkinter / psutil，
   让 `import stw_ui` 变得又慢又脆。要用什么就显式 `from stw_ui import xxx`。
"""
import os
import sys

__version__ = "0.3.0"

_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_BASE_DIR = os.path.dirname(_PKG_DIR)
for _p in (_BASE_DIR, _PKG_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

__all__ = ["__version__"]
