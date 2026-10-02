param(
    [string]$Preflight = "runtime/preflight.json",
    [string]$Output = "runtime/pilot-readiness-pack.md"
)

$ErrorActionPreference = "Stop"
python src/generate_pilot_pack.py --preflight $Preflight --output $Output

