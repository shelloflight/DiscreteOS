<#
.SYNOPSIS
    D-OS cross-platform host tool bootstrapper (Windows).
    Compiles tools/dbuild on demand and forwards all arguments to dbuild.exe.
#>
$ErrorActionPreference = 'Stop'

$Root = $PSScriptRoot
$Crate = Join-Path $Root 'tools\dbuild'
$Bin = Join-Path $Crate 'target\release\dbuild.exe'

function Find-Cargo {
    $cmd = Get-Command cargo -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $boxes = @($env:DOS_RUST_BOX, (Join-Path (Split-Path $Root -Parent) 'Devbox\boxes\rust')) | Where-Object { $_ }
    foreach ($box in $boxes) {
        $p = Join-Path $box 'cargo\bin\cargo.exe'
        if (Test-Path $p) {
            $env:RUSTUP_HOME = Join-Path $box 'rustup'
            $env:CARGO_HOME  = Join-Path $box 'cargo'
            $env:PATH = "$(Join-Path $box 'cargo\bin');$(Join-Path $box 'mingw64\bin');$env:PATH"
            return $p
        }
    }
    throw "Rust toolchain (cargo) not found on PATH or DOS_RUST_BOX. See docs/building.md."
}

$needBuild = -not (Test-Path $Bin)
if (-not $needBuild) {
    $binTime = (Get-Item $Bin).LastWriteTimeUtc
    $watch = @(Get-ChildItem (Join-Path $Crate 'src') -Filter *.rs -Recurse) +
             @(Get-Item (Join-Path $Crate 'Cargo.toml')) +
             @(Get-ChildItem (Join-Path $Root 'user\lib\fs\src') -Filter *.rs -Recurse) +
             @(Get-ChildItem (Join-Path $Root 'user\lib\crypto\src') -Filter *.rs -Recurse) +
             @(Get-ChildItem (Join-Path $Root 'user\lib\net\src') -Filter *.rs -Recurse) +
             @(Get-ChildItem (Join-Path $Root 'user\lib\font\src') -Filter *.rs -Recurse) +
             @(Get-ChildItem (Join-Path $Root 'user\lib\app\src') -Filter *.rs -Recurse) +
             @(Get-ChildItem (Join-Path $Root 'user\lib\identity\src') -Filter *.rs -Recurse)
    if (@($watch | Where-Object { $_.LastWriteTimeUtc -gt $binTime }).Count -gt 0) {
        $needBuild = $true
    }
}

if ($needBuild) {
    $cargo = Find-Cargo
    $cargoArgs = [Collections.Generic.List[string]]@('build', '--release', '--quiet')
    if (Test-Path (Join-Path $Crate 'Cargo.lock')) { $cargoArgs.Add('--locked') }
    Push-Location $Crate
    try {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { & $cargo @cargoArgs 2>&1 | ForEach-Object { "$_" } | Out-Host }
        finally { $ErrorActionPreference = $prev }
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally { Pop-Location }
}

& $Bin @args
exit $LASTEXITCODE
