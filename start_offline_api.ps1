param(
    [string]$Model = "llama3.2:1b"
)

$ErrorActionPreference = "Stop"
$OllamaUrl = "http://127.0.0.1:11435"
$modelDirectory = Join-Path $PSScriptRoot "data\ollama_models"
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
    $ollamaPath = $null
}
$modelReady = $false
if ($ollamaPath) {
    try { Invoke-RestMethod -Uri "$OllamaUrl/api/tags" -TimeoutSec 2 | Out-Null }
    catch {
        Start-Process -FilePath $ollamaPath -ArgumentList "serve" -WindowStyle Hidden
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            Start-Sleep -Milliseconds 500
            try { Invoke-RestMethod -Uri "$OllamaUrl/api/tags" -TimeoutSec 2 | Out-Null; break }
            catch { }
        }
    }
    try {
        $modelList = & $ollamaPath list 2>&1
        $escapedModel = [regex]::Escape($Model)
        $modelReady = ($LASTEXITCODE -eq 0) -and (($modelList -join "`n") -match "(?m)^$escapedModel(?:\s|$)")
    } catch { $modelReady = $false }
}

if ($modelReady) {
    $env:CYBER_LLM_MODEL = $Model
    $env:CYBER_OLLAMA_URL = $OllamaUrl
    Write-Host "Starting Cyber API with local model '$Model'."
} else {
    Remove-Item Env:CYBER_LLM_MODEL -ErrorAction SilentlyContinue
    Remove-Item Env:CYBER_OLLAMA_URL -ErrorAction SilentlyContinue
    Write-Warning "The optional local LLM is unavailable. Starting the dashboard and detection API in retrieval-only mode. Install it later with .\install_offline_model.ps1."
}
& (Join-Path $PSScriptRoot "recovery_venv\Scripts\python.exe") (Join-Path $PSScriptRoot "api.py")
exit $LASTEXITCODE
