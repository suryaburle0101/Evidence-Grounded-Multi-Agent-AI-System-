param([string]$Model = "llama3.2:1b")

$ErrorActionPreference = "Stop"
$modelDirectory = Join-Path $PSScriptRoot "data\ollama_models"
$ollamaUrl = "http://127.0.0.1:11435"
New-Item -ItemType Directory -Path $modelDirectory -Force | Out-Null
$env:OLLAMA_MODELS = $modelDirectory
$env:OLLAMA_HOST = "127.0.0.1:11435"
$env:OLLAMA_NO_CLOUD = "1"
foreach ($proxyName in @("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")) {
    Remove-Item "Env:$proxyName" -ErrorAction SilentlyContinue
}

$ollama = Get-Command ollama -ErrorAction SilentlyContinue
$ollamaPath = if ($ollama) {
    $ollama.Source
} else {
    Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"
}
if (-not (Test-Path -LiteralPath $ollamaPath)) {
    throw "Ollama is not installed. Install the signed Ollama Windows application first."
}

$ready = $false
try {
    Invoke-RestMethod -Uri "$ollamaUrl/api/tags" -TimeoutSec 2 | Out-Null
    $ready = $true
} catch { }
if (-not $ready) {
    Start-Process -FilePath $ollamaPath -ArgumentList "serve" -WindowStyle Hidden
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Milliseconds 500
        try {
            Invoke-RestMethod -Uri "$ollamaUrl/api/tags" -TimeoutSec 2 | Out-Null
            $ready = $true
            break
        } catch { }
    }
}
if (-not $ready) {
    throw "Could not start the local Ollama service at $ollamaUrl."
}

& $ollamaPath pull $Model
if ($LASTEXITCODE -ne 0) {
    throw "Ollama could not download '$Model'. Check the local service and network, then rerun this script."
}
Write-Host "Model '$Model' is installed in $modelDirectory."
