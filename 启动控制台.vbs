Set sh = CreateObject("Wscript.Shell")
sh.CurrentDirectory = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
sh.Run ".venv\Scripts\pythonw.exe -m stw_ui.stw_ui", 0,   False