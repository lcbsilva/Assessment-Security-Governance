[CmdletBinding()]
param(
    [string]$HistoryDir = "runtime/history",
    [string]$Output = "dist/history-dashboard.html"
)

$ErrorActionPreference = "Stop"
python src/history_dashboard.py --history-dir $HistoryDir --output $Output
if ($LASTEXITCODE -ne 0) { throw "Falha ao gerar dashboard histórico." }
