<#
  package/build_package.ps1

  Build a portable zip for YinHuGuard.

  DELIBERATELY PURE ASCII. Chinese string literals inside a .ps1 get mangled
  by the console codepage on this machine (measured: a Chinese filename read
  back as mojibake). All Chinese content therefore lives in separate files
  with ASCII names -- package\README-zh.md is copied to README-zh.txt in the
  bundle. Do not add Chinese literals to this file.

  Produces: dist\yinhuguard-<yyyyMMdd>.zip containing
    yinhuguard_app.exe   (renamed to YinHuGuard.exe in the bundle)
    yinhuguard_engine.dll
    rules.json
    flutter_windows.dll
    data\                (Flutter assets)
    README-zh.txt

  Phase 1 is unsigned. SmartScreen will warn on first run; README-zh.txt
  explains how to proceed.
#>

[CmdletBinding()]
param(
  # Skip the rebuild steps and only re-zip an existing app Release output.
  [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$engineBuild = Join-Path $repoRoot 'engine\build'
$appDir = Join-Path $repoRoot 'app'
$appRelease = Join-Path $appDir 'build\windows\x64\runner\Release'
$engineDll = Join-Path $engineBuild 'Release\yinhuguard_engine.dll'
$rulesJson = Join-Path $repoRoot 'rules\rules.json'
$readmeSrc = Join-Path $PSScriptRoot 'README-zh.md'

$distRoot = Join-Path $repoRoot 'dist'
$bundleName = 'yinhuguard'
$bundleDir = Join-Path $distRoot $bundleName
$stamp = Get-Date -Format 'yyyyMMdd'
$zipPath = Join-Path $distRoot "yinhuguard-$stamp.zip"

function Invoke-Step {
  param([string]$Label, [scriptblock]$Body)
  Write-Host "==> $Label"
  & $Body
  if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
    throw "$Label failed with exit code $LASTEXITCODE"
  }
}

if (-not $SkipBuild) {
  Invoke-Step 'configure engine (Visual Studio 18 2026, x64)' {
    # The generator MUST be named: this machine's default is Ninja, which
    # rejects -A x64 with a confusing message.
    cmake -S (Join-Path $repoRoot 'engine') -B $engineBuild `
      -G 'Visual Studio 18 2026' -A x64
  }
  Invoke-Step 'build engine' {
    cmake --build $engineBuild --config Release
  }
  Invoke-Step 'build Flutter app' {
    Push-Location $appDir
    try { flutter build windows --release } finally { Pop-Location }
  }
}

foreach ($required in @($appRelease, $engineDll, $rulesJson, $readmeSrc)) {
  if (-not (Test-Path -LiteralPath $required)) {
    throw "required input missing: $required"
  }
}

if (Test-Path -LiteralPath $bundleDir) {
  Remove-Item -LiteralPath $bundleDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $bundleDir | Out-Null

Invoke-Step 'copy Flutter Release output' {
  Copy-Item -Path (Join-Path $appRelease '*') -Destination $bundleDir -Recurse -Force
}

Invoke-Step 'copy rules.json' {
  Copy-Item -LiteralPath $rulesJson -Destination (Join-Path $bundleDir 'rules.json') -Force
}

Invoke-Step 'copy engine DLL' {
  Copy-Item -LiteralPath $engineDll -Destination $bundleDir -Force
}

Invoke-Step 'copy first-run README' {
  Copy-Item -LiteralPath $readmeSrc -Destination (Join-Path $bundleDir 'README-zh.txt') -Force
}

# Rename the entry exe. The engine DLL is located by the app relative to the
# exe, so renaming the exe is safe; renaming the DLL is not.
$builtExe = Join-Path $bundleDir 'yinhuguard_app.exe'
if (Test-Path -LiteralPath $builtExe) {
  Invoke-Step 'rename entry executable' {
    Move-Item -LiteralPath $builtExe -Destination (Join-Path $bundleDir 'YinHuGuard.exe') -Force
  }
}

if (Test-Path -LiteralPath $zipPath) {
  Remove-Item -LiteralPath $zipPath -Force
}
Invoke-Step 'compress' {
  Compress-Archive -Path (Join-Path $bundleDir '*') -DestinationPath $zipPath -Force
}

# Verify the archive actually carries everything. A zip that silently misses
# the engine DLL produces an exe that starts and reports "engine not found" --
# which looks like a broken tool rather than a broken package.
Write-Host '==> verify archive contents'
$checkDir = Join-Path $distRoot '_verify'
if (Test-Path -LiteralPath $checkDir) {
  Remove-Item -LiteralPath $checkDir -Recurse -Force
}
Expand-Archive -LiteralPath $zipPath -DestinationPath $checkDir -Force

$mustExist = @(
  'YinHuGuard.exe',
  'rules.json',
  'yinhuguard_engine.dll',
  'flutter_windows.dll',
  'README-zh.txt'
)
$missing = @()
foreach ($item in $mustExist) {
  if (-not (Test-Path -LiteralPath (Join-Path $checkDir $item))) {
    $missing += $item
  }
}
if (-not (Test-Path -LiteralPath (Join-Path $checkDir 'data'))) {
  $missing += 'data\'
}

if ($missing.Count -gt 0) {
  throw ("archive is missing: " + ($missing -join ', '))
}

Remove-Item -LiteralPath $checkDir -Recurse -Force

$sizeMb = [math]::Round((Get-Item -LiteralPath $zipPath).Length / 1MB, 1)
Write-Host ''
Write-Host "OK  $zipPath  ($sizeMb MB)"
Write-Host "    verified: $($mustExist -join ', '), data\"
