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
    [string]$OutputDir,

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
$ExpectedMakefileSha256 =
    "e6f7710cd32be5050e10234f3282d2512b58d28170d5de14f96c30478ac03725"
$ExpectedMainObjectSha256 =
    "ff736a313b4d8d53747a7b113fff5a310c31c4218555ffbf1570537af15dd6be"
$ExpectedDieScriptObjectSha256 =
    "f74138c8acbf6a7427c90761c7bfbf7715c3dfda6e1c4def3715d348ac159a19"
$Profiles = @(
    [ordered]@{
        name = "bw"
        source = "bw_dispatch_harness_main.cpp"
        target = "die-bw-dispatch-harness.exe"
        adapt_database_paths = $false
    },
    [ordered]@{
        name = "npm"
        source = "npm_dispatch_harness_main.cpp"
        target = "die-npm-dispatch-harness.exe"
        adapt_database_paths = $true
    },
    [ordered]@{
        name = "generic_archive"
        source = "generic_archive_dispatch_harness_main.cpp"
        target = "die-generic-archive-dispatch-harness.exe"
        adapt_database_paths = $true
    }
)

function Resolve-ExistingPath {
    param([string]$Path, [string]$Description)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Description does not exist: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).
        Hash.ToLowerInvariant()
}

function Assert-Equal {
    param([string]$Actual, [string]$Expected, [string]$Description)
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
Assert-Equal $RulesCommit $ExpectedRulesCommit "Detect-It-Easy commit"

$Qmake = Resolve-ExistingPath (Join-Path $QtDir "bin\qmake.exe") "qmake"
$QtCore = Resolve-ExistingPath (
    Join-Path $QtDir "bin\Qt5Core.dll"
) "Qt5Core"
$QtScript = Resolve-ExistingPath (
    Join-Path $QtDir "bin\Qt5Script.dll"
) "Qt5Script"
Assert-Equal (Get-Sha256 $Qmake) $ExpectedQmakeSha256 "qmake SHA-256"
Assert-Equal (Get-Sha256 $QtCore) $ExpectedQtCoreSha256 "Qt5Core SHA-256"
Assert-Equal (Get-Sha256 $QtScript) $ExpectedQtScriptSha256 `
    "Qt5Script SHA-256"

$Cli = Resolve-ExistingPath (
    Join-Path $SourceDir "build\release\diec.exe"
) "fixed CLI artifact"
Assert-Equal (Get-Sha256 $Cli) $ExpectedCliSha256 "CLI SHA-256"

$ConsoleBuild = Resolve-ExistingPath (
    Join-Path $BuildDir "console_source"
) "console qmake build directory"
$Makefile = Resolve-ExistingPath (
    Join-Path $ConsoleBuild "Makefile.Release"
) "console Release Makefile"
$MainObject = Resolve-ExistingPath (
    Join-Path $ConsoleBuild "release\main_console.obj"
) "console main object"
$DieScriptObject = Resolve-ExistingPath (
    Join-Path $ConsoleBuild "release\die_script.obj"
) "die_script object"
Assert-Equal (Get-Sha256 $Makefile) $ExpectedMakefileSha256 `
    "Release Makefile SHA-256"
Assert-Equal (Get-Sha256 $MainObject) $ExpectedMainObjectSha256 `
    "main_console object SHA-256"
Assert-Equal (Get-Sha256 $DieScriptObject) $ExpectedDieScriptObjectSha256 `
    "die_script object SHA-256"

$OriginalMakefile = [System.IO.File]::ReadAllText($Makefile)
$TargetMatch = [regex]::Match(
    $OriginalMakefile,
    "(?m)^DESTDIR_TARGET\s*=\s*(.+)\r?$"
)
$SourceMatch = [regex]::Match(
    $OriginalMakefile,
    "[^\s]+console_source\\main_console\.cpp"
)
if (-not $TargetMatch.Success -or -not $SourceMatch.Success) {
    throw "Cannot locate the original console target or source."
}
$OriginalTarget = $TargetMatch.Groups[1].Value.Trim()

$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}
$DatabaseRoot = "Detect-It-Easy"
$DatabaseReplacements = [ordered]@{
    "/opt/die-source/Detect-It-Easy/db_custom" = "$DatabaseRoot/db_custom"
    "/opt/die-source/Detect-It-Easy/db_extra" = "$DatabaseRoot/db_extra"
    "/opt/die-source/Detect-It-Easy/db" = "$DatabaseRoot/db"
}

$Timer = [System.Diagnostics.Stopwatch]::StartNew()
$Artifacts = [ordered]@{}
$SourceRecords = [ordered]@{}
foreach ($Profile in $Profiles) {
    $HarnessSource = Resolve-ExistingPath (
        Join-Path $ScriptRoot $Profile.source
    ) "$($Profile.name) harness source"
    $OriginalSource = [System.IO.File]::ReadAllText($HarnessSource)
    $LocalSourceText = $OriginalSource
    $AppliedReplacements = @()
    if ($Profile.adapt_database_paths) {
        foreach ($Entry in $DatabaseReplacements.GetEnumerator()) {
            $Count = (
                $LocalSourceText.Length -
                $LocalSourceText.Replace($Entry.Key, "").Length
            ) / $Entry.Key.Length
            if ($Count -ne 1) {
                throw (
                    "$($Profile.name) database path occurrence differs: " +
                    "$($Entry.Key) ($Count)"
                )
            }
            $LocalSourceText = $LocalSourceText.Replace(
                $Entry.Key,
                $Entry.Value
            )
            $AppliedReplacements += [ordered]@{
                from = $Entry.Key
                to = $Entry.Value
                count = 1
            }
        }
    }
    $LocalHarness = Join-Path $ConsoleBuild $Profile.source
    [System.IO.File]::WriteAllText(
        $LocalHarness,
        $LocalSourceText,
        [System.Text.UTF8Encoding]::new($false)
    )

    $ObjectStem = [System.IO.Path]::GetFileNameWithoutExtension(
        $Profile.source
    )
    $ObjectName = "release\$ObjectStem.obj"
    $HarnessMakefile = Join-Path `
        $ConsoleBuild `
        "Makefile.Dispatch.$($Profile.name).Release"
    $PatchedMakefile = $OriginalMakefile.Replace(
        "release\main_console.obj",
        $ObjectName
    ).Replace(
        $SourceMatch.Value,
        $Profile.source
    ).Replace(
        $OriginalTarget,
        $Profile.target
    )
    if (
        $PatchedMakefile.Contains("release\main_console.obj") -or
        $PatchedMakefile.Contains($SourceMatch.Value) -or
        $PatchedMakefile.Contains($OriginalTarget)
    ) {
        throw "$($Profile.name) Makefile replacement was incomplete."
    }
    [System.IO.File]::WriteAllText(
        $HarnessMakefile,
        $PatchedMakefile,
        [System.Text.UTF8Encoding]::new($false)
    )

    $HarnessObject = Join-Path $ConsoleBuild $ObjectName
    $BuiltHarnessPath = Join-Path $ConsoleBuild $Profile.target
    foreach ($GeneratedPath in @($HarnessObject, $BuiltHarnessPath)) {
        if (Test-Path -LiteralPath $GeneratedPath) {
            Remove-Item -LiteralPath $GeneratedPath -Force
        }
    }
    $BuildCommand = @(
        "call `"$VsDevCmd`" -arch=amd64 -host_arch=amd64",
        "cd /d `"$ConsoleBuild`"",
        (
            "nmake /NOLOGO /F " +
            "`"Makefile.Dispatch.$($Profile.name).Release`" " +
            "`"$($Profile.target)`""
        )
    ) -join " && "
    & $env:ComSpec /d /c $BuildCommand
    if ($LASTEXITCODE -ne 0) {
        throw "$($Profile.name) harness build failed: $LASTEXITCODE"
    }

    $BuiltHarness = Resolve-ExistingPath $BuiltHarnessPath `
        "$($Profile.name) built harness"
    $OutputBinary = Join-Path $OutputDir $Profile.target
    [System.IO.File]::Copy($BuiltHarness, $OutputBinary, $true)
    $OutputBinary = Resolve-ExistingPath $OutputBinary `
        "$($Profile.name) output harness"
    $Artifacts[$Profile.name] = [ordered]@{
        filename = $Profile.target
        size = (Get-Item -LiteralPath $OutputBinary).Length
        sha256 = Get-Sha256 $OutputBinary
    }
    $SourceRecords[$Profile.name] = [ordered]@{
        path = "tools/upstream/$($Profile.source)"
        original_sha256 = Get-Sha256 $HarnessSource
        adapted_sha256 = Get-Sha256 $LocalHarness
        database_path_replacements = $AppliedReplacements
    }
}
$Timer.Stop()

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
        original_die_script_object_sha256 = Get-Sha256 $DieScriptObject
        replaced_object = "release/main_console.obj"
        harness_count = $Profiles.Count
        database_root = "<working-directory>/Detect-It-Easy"
        runtime_working_directory_contract = "verified-source-root"
        engine_objects_modified = $false
    }
    source_hashes = [ordered]@{
        builder = Get-Sha256 $MyInvocation.MyCommand.Path
        harnesses = $SourceRecords
    }
    artifacts = $Artifacts
}

$Json = $Result | ConvertTo-Json -Depth 10
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
