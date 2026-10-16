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
  # **Explicit allowlist, NOT a wildcard copy.**
  #
  # This used to be `Copy-Item -Recurse -Force $appRelease\*`, which swept
  # runtime output into the shipped bundle: the app writes its scan log and
  # JSON report next to the exe, and the tool had been run directly out of
  # this Release directory, so `reports\` (12+ logs carrying the developer
  # machine's real paths) and a stray `$v\` directory ended up in the zip
  # pasted onto a clean install.
  #
  # A security tool that hands the user its own scan history is the exact
  # opposite of what the README promises about not leaving data lying around.
  # Anything not listed here does not ship -- that is the point.
  # rules.json and the engine DLL are copied explicitly just below from their
  # canonical locations, so they are deliberately not in this list.
  $copyList = @(
    'yinhuguard_app.exe',
    'flutter_windows.dll',
    'native_assets.json',
    'data'
  )
  foreach ($item in $copyList) {
    $src = Join-Path $appRelease $item
    if (-not (Test-Path -LiteralPath $src)) {
      throw "expected build output missing: $src"
    }
    Copy-Item -LiteralPath $src -Destination $bundleDir -Recurse -Force
  }

  # The app writes its log and report into `reports\` next to the exe. That
  # directory must never exist in a freshly built bundle; if it does, the
  # build output was polluted by someone running the exe in place.
  foreach ($junk in @('reports', '$v')) {
    $junkPath = Join-Path $bundleDir $junk
    if (Test-Path -LiteralPath $junkPath) {
      throw ("build output is polluted by runtime artifacts: " + $junkPath +
             " -- run the exe from a clean copy, not from this directory")
    }
  }
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
$mustNotExist = @(
  # Scan logs and reports from the developer's machine. These once shipped.
  'reports\'
  '$v\'
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
# The AOT blob is the whole Dart side; a bundle without it starts and reports
# "engine not found", which reads as a broken package rather than a bad build.
foreach ($blob in @('data\app.so', 'data\flutter_assets')) {
  if (-not (Test-Path -LiteralPath (Join-Path $checkDir $blob))) {
    $missing += $blob
  }
}

if ($missing.Count -gt 0) {
  throw ("archive is missing: " + ($missing -join ', '))
}

$leaked = @()
foreach ($item in $mustNotExist) {
  if (Test-Path -LiteralPath (Join-Path $checkDir $item)) {
    $leaked += $item
  }
}
if ($leaked.Count -gt 0) {
  throw ("archive leaks runtime artifacts: " + ($leaked -join ', ') +
         " -- these contain real paths from this machine and must not ship")
}

Remove-Item -LiteralPath $checkDir -Recurse -Force

$sizeMb = [math]::Round((Get-Item -LiteralPath $zipPath).Length / 1MB, 1)
Write-Host ''
Write-Host "OK  $zipPath  ($sizeMb MB)"
Write-Host "    verified: $($mustExist -join ', '), data\"
