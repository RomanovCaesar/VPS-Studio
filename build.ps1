$ErrorActionPreference = "Stop"

cargo check
cargo build --release

Write-Host "Built $PSScriptRoot\target\release\vps-studio.exe"
