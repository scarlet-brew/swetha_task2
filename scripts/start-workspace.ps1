param([int]$Port = 8768)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { throw 'The project Python environment is missing. Follow the repository setup instructions first.' }
# Load only the expected provider credential into this process; never print it.
# An existing environment value always wins over the local development file.
if (-not $env:ANTHROPIC_API_KEY) {
    $localConfig = Join-Path $projectRoot '.env'
    if (Test-Path -LiteralPath $localConfig) {
        foreach ($line in [System.IO.File]::ReadAllLines($localConfig)) {
            if ($line -match '^\s*(?:export\s+)?ANTHROPIC_API_KEY\s*=\s*(.*?)\s*$') {
                $credentialValue = $Matches[1].Trim().Trim('"').Trim("'")
                if ($credentialValue) { $env:ANTHROPIC_API_KEY = $credentialValue }
                break
            }
        }
    }
}
& $pythonPath (Join-Path $projectRoot 'app\workspace_server.py') --port $Port
exit $LASTEXITCODE
