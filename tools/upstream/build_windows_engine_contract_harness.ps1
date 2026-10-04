[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceDir,

    [Parameter(Mandatory = $true)]
    [string]$BuildDir,

    [Parameter(Mandatory = $true)]
    [string]$QtDir,

    [Parameter(Mandatory = $true)]
    [string]$VsDevCmd,

    [Parameter(Mandatory = $true)]
    [string]$OutputBinary,

    [string]$OutputJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ExpectedCommit = "74eaf505c250ab47e709024e9dc41657cd8f2254"
$ExpectedRulesCommit = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
$ExpectedSubmoduleCount = 58
$ExpectedCliSha256 =
    "e8579a6ed0d2536ea14af154bcbeeaaea6967c0c7559a595fb3fe52206ac635e"
$ExpectedQmakeSha256 =
    "e873ad3a689a0628c3037a6440221dcd2e426395edf14ffa6379612dede26d36"
$ExpectedQtCoreSha256 =
    "8d2ff4ce9096ddccc4f4cd62c2e41fc854cfd1b0d6e8d296645a7f5fd4ae565a"
$ExpectedQtScriptSha256 =
    "0b58e5e79df13110a8258f14d7b3658d1dd0c8dddc337a164b89d4ac12a0638f"

function Resolve-ExistingPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Description does not exist: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Get-Sha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).
        Hash.ToLowerInvariant()
}

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Actual,

        [Parameter(Mandatory = $true)]
        [string]$Expected,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if ($Actual -cne $Expected) {
        throw "$Description mismatch: expected $Expected, got $Actual"
    }
}

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows
    )) {
    throw "This harness builder only supports Windows."
}

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceDir = Resolve-ExistingPath $SourceDir "source directory"
$BuildDir = Resolve-ExistingPath $BuildDir "qmake build directory"
$QtDir = Resolve-ExistingPath $QtDir "Qt directory"
$VsDevCmd = Resolve-ExistingPath $VsDevCmd "Visual Studio command"
$HarnessSource = Resolve-ExistingPath(
    (Join-Path $ScriptRoot "engine_contract_harness_main.cpp")
) "shared harness source"

$RootCommit = (& git -C $SourceDir rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read DIE-engine HEAD."
}
Assert-Equal $RootCommit $ExpectedCommit "DIE-engine commit"

$RootStatus = @(
    & git -C $SourceDir status --porcelain=v1 --untracked-files=no `
        --ignore-submodules=dirty
)
if ($LASTEXITCODE -ne 0 -or $RootStatus.Count -ne 0) {
    throw "DIE-engine tracked state is not clean."
}
$SubmoduleStatus = @(& git -C $SourceDir submodule status --recursive)
if (
    $LASTEXITCODE -ne 0 -or
    $SubmoduleStatus.Count -ne $ExpectedSubmoduleCount -or
    @($SubmoduleStatus | Where-Object { $_[0] -ne " " }).Count -ne 0
) {
    throw "DIE-engine recursive submodule identity differs."
}
$RulesCommit = (& git -C (Join-Path $SourceDir "Detect-It-Easy") `
    rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read Detect-It-Easy HEAD."
}
Assert-Equal $RulesCommit $ExpectedRulesCommit "Detect-It-Easy commit"

$Qmake = Resolve-ExistingPath(
    (Join-Path $QtDir "bin\qmake.exe")
) "qmake"
$QtCore = Resolve-ExistingPath(
    (Join-Path $QtDir "bin\Qt5Core.dll")
) "Qt5Core"
$QtScript = Resolve-ExistingPath(
    (Join-Path $QtDir "bin\Qt5Script.dll")
) "Qt5Script"
Assert-Equal (Get-Sha256 $Qmake) $ExpectedQmakeSha256 "qmake SHA-256"
Assert-Equal (Get-Sha256 $QtCore) $ExpectedQtCoreSha256 `
    "Qt5Core SHA-256"
Assert-Equal (Get-Sha256 $QtScript) $ExpectedQtScriptSha256 `
    "Qt5Script SHA-256"

$Cli = Resolve-ExistingPath(
    (Join-Path $SourceDir "build\release\diec.exe")
) "fixed CLI artifact"
Assert-Equal (Get-Sha256 $Cli) $ExpectedCliSha256 "CLI SHA-256"

$ConsoleBuild = Resolve-ExistingPath(
    (Join-Path $BuildDir "console_source")
) "console qmake build directory"
$Makefile = Resolve-ExistingPath(
    (Join-Path $ConsoleBuild "Makefile.Release")
) "console Release Makefile"
$MainObject = Resolve-ExistingPath(
    (Join-Path $ConsoleBuild "release\main_console.obj")
) "console main object"

$OriginalMakefile = [System.IO.File]::ReadAllText($Makefile)
$TargetMatch = [regex]::Match(
    $OriginalMakefile,
    "(?m)^DESTDIR_TARGET\s*=\s*(.+)\r?$"
)
if (-not $TargetMatch.Success) {
    throw "Cannot locate DESTDIR_TARGET in the Release Makefile."
}
$OriginalTarget = $TargetMatch.Groups[1].Value.Trim()
$SourceMatch = [regex]::Match(
    $OriginalMakefile,
    "[^\s]+console_source\\main_console\.cpp"
)
if (-not $SourceMatch.Success) {
    throw "Cannot locate main_console.cpp in the Release Makefile."
}

$HarnessTarget = "die-engine-contract-harness.exe"
$HarnessObjectName = "release\engine_contract_harness_main.obj"
$PatchedMakefile = $OriginalMakefile.Replace(
    "release\main_console.obj",
    $HarnessObjectName
).Replace(
    $SourceMatch.Value,
    "engine_contract_harness_main.cpp"
).Replace(
    $OriginalTarget,
    $HarnessTarget
)
if (
    $PatchedMakefile.Contains("release\main_console.obj") -or
    $PatchedMakefile.Contains($SourceMatch.Value) -or
    $PatchedMakefile.Contains($OriginalTarget)
) {
    throw "Release Makefile replacement was incomplete."
}

$LocalHarness = Join-Path $ConsoleBuild "engine_contract_harness_main.cpp"
$HarnessMakefile = Join-Path $ConsoleBuild "Makefile.EngineContract.Release"
[System.IO.File]::Copy($HarnessSource, $LocalHarness, $true)
[System.IO.File]::WriteAllText(
    $HarnessMakefile,
    $PatchedMakefile,
    [System.Text.UTF8Encoding]::new($false)
)
$HarnessObject = Join-Path $ConsoleBuild $HarnessObjectName
$BuiltHarnessPath = Join-Path $ConsoleBuild $HarnessTarget
foreach ($GeneratedPath in @($HarnessObject, $BuiltHarnessPath)) {
    if (Test-Path -LiteralPath $GeneratedPath) {
        Remove-Item -LiteralPath $GeneratedPath -Force
    }
}

$BuildCommand = @(
    "call `"$VsDevCmd`" -arch=amd64 -host_arch=amd64",
    "cd /d `"$ConsoleBuild`"",
    "nmake /NOLOGO /F Makefile.EngineContract.Release $HarnessTarget"
) -join " && "
$Timer = [System.Diagnostics.Stopwatch]::StartNew()
& $env:ComSpec /d /c $BuildCommand
$BuildExitCode = $LASTEXITCODE
$Timer.Stop()
if ($BuildExitCode -ne 0) {
    throw "Windows engine-contract harness build failed: $BuildExitCode"
}

$BuiltHarness = Resolve-ExistingPath(
    $BuiltHarnessPath
) "built engine-contract harness"
$OutputParent = Split-Path -Parent $OutputBinary
if ($OutputParent -and -not (Test-Path -LiteralPath $OutputParent)) {
    New-Item -ItemType Directory -Path $OutputParent | Out-Null
}
[System.IO.File]::Copy(
    $BuiltHarness,
    [System.IO.Path]::GetFullPath($OutputBinary),
    $true
)
$OutputBinary = Resolve-ExistingPath(
    $OutputBinary
) "output engine-contract harness"

$Result = [ordered]@{
    schema_version = 1
    baseline = [ordered]@{
        repository = "https://github.com/horsicq/DIE-engine"
        commit = $RootCommit
        recursive_submodule_count = $SubmoduleStatus.Count
        rules_commit = $RulesCommit
        cli_sha256 = $ExpectedCliSha256
    }
    qt = [ordered]@{
        version = (& $Qmake -query QT_VERSION).Trim()
        qmake_spec = (& $Qmake -query QMAKE_SPEC).Trim()
        qmake_sha256 = Get-Sha256 $Qmake
        qt5core_sha256 = Get-Sha256 $QtCore
        qt5script_sha256 = Get-Sha256 $QtScript
    }
    build = [ordered]@{
        system = "patched-qmake-release-makefile"
        tool = "nmake"
        target_architecture = "amd64"
        host_architecture = "amd64"
        elapsed_milliseconds = $Timer.ElapsedMilliseconds
        original_makefile_sha256 = Get-Sha256 $Makefile
        original_main_object_sha256 = Get-Sha256 $MainObject
        replaced_object = "release/main_console.obj"
        harness_object = "release/engine_contract_harness_main.obj"
    }
    source_hashes = [ordered]@{
        builder = Get-Sha256 $MyInvocation.MyCommand.Path
        shared_harness = Get-Sha256 $HarnessSource
    }
    artifact = [ordered]@{
        filename = Split-Path -Leaf $OutputBinary
        size = (Get-Item -LiteralPath $OutputBinary).Length
        sha256 = Get-Sha256 $OutputBinary
    }
}

$Json = $Result | ConvertTo-Json -Depth 8
if ($OutputJson) {
    $JsonParent = Split-Path -Parent $OutputJson
    if ($JsonParent -and -not (Test-Path -LiteralPath $JsonParent)) {
        New-Item -ItemType Directory -Path $JsonParent | Out-Null
    }
    [System.IO.File]::WriteAllText(
        [System.IO.Path]::GetFullPath($OutputJson),
        "$Json`n",
        [System.Text.UTF8Encoding]::new($false)
    )
}
$Json
