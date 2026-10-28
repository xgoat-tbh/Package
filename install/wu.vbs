' Windowless launcher. wscript never creates a console.
' The boot claim and the HIGHEST scheduled task own elevation, so the shim
' itself must never raise a UAC prompt.
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")
here = fso.GetParentFolderName(WScript.ScriptFullName)
sh.Run """" & here & "\WindowsUpdateService.cmd""", 0, False
