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
$ExpectedMakefileSha256 =
    "e6f7710cd32be5050e10234f3282d2512b58d28170d5de14f96c30478ac03725"
$ExpectedMainObjectSha256 =
    "ff736a313b4d8d53747a7b113fff5a310c31c4218555ffbf1570537af15dd6be"
$ExpectedHarnessSha256 =
    "b8f35799ddda9e61fcff70081e7cdb6550ca2b9e9442a340a8b4ff31d2170e41"

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
$HarnessSource = Resolve-ExistingPath (
    Join-Path $ScriptRoot "archive_iteration_boundary_harness_main.cpp"
) "archive-iteration harness source"
Assert-Equal (Get-Sha256 $HarnessSource) $ExpectedHarnessSha256 `
    "archive-iteration harness source SHA-256"

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
Assert-Equal (Get-Sha256 $Makefile) $ExpectedMakefileSha256 `
    "Release Makefile SHA-256"
Assert-Equal (Get-Sha256 $MainObject) $ExpectedMainObjectSha256 `
    "main_console object SHA-256"

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
    throw "Cannot locate original target or console source."
}
$OriginalTarget = $TargetMatch.Groups[1].Value.Trim()
$HarnessTarget = "die-archive-iteration-harness.exe"
$HarnessObjectName = "release\archive_iteration_boundary_harness_main.obj"
$PatchedMakefile = $OriginalMakefile.Replace(
    "release\main_console.obj",
    $HarnessObjectName
).Replace(
    $SourceMatch.Value,
    "archive_iteration_boundary_harness_main.cpp"
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

$OriginalSource = [System.IO.File]::ReadAllText($HarnessSource)
$UnixRssFunction = @'
qlonglong peakRssKiB()
{
    struct rusage usage = {};
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        return -1;
    }
    return usage.ru_maxrss;
}
'@
$UnixRssFunction = $UnixRssFunction.Replace("`r`n", "`n")
$WindowsRssFunction = @'
qlonglong peakRssKiB()
{
    PROCESS_MEMORY_COUNTERS counters = {};
    counters.cb = sizeof(counters);
    if (!GetProcessMemoryInfo(
            GetCurrentProcess(),
            &counters,
            sizeof(counters)
        )) {
        return -1;
    }
    return static_cast<qlonglong>(
        counters.PeakWorkingSetSize / 1024
    );
}
'@
$WindowsRssFunction = $WindowsRssFunction.Replace("`r`n", "`n")
$IncludeToken = "#include <sys/resource.h>"
$IncludeCount = (
    $OriginalSource.Length -
    $OriginalSource.Replace($IncludeToken, "").Length
) / $IncludeToken.Length
$RssFirstIndex = $OriginalSource.IndexOf($UnixRssFunction)
$RssLastIndex = $OriginalSource.LastIndexOf($UnixRssFunction)
if (
    $IncludeCount -ne 1 -or
    $RssFirstIndex -lt 0 -or
    $RssFirstIndex -ne $RssLastIndex
) {
    throw (
        "archive-iteration platform adaptation source drift: " +
        "include=$IncludeCount rssFirst=$RssFirstIndex " +
        "rssLast=$RssLastIndex"
    )
}
$AdaptedSource = $OriginalSource.Replace(
    "#include <sys/resource.h>",
    (
        "#include <windows.h>`n" +
        "#include <psapi.h>`n`n" +
        "#pragma comment(lib, `"psapi.lib`")"
    )
)
$AdaptedSource = [regex]::Replace(
    $AdaptedSource,
    [regex]::Escape($UnixRssFunction),
    $WindowsRssFunction,
    1
)
$Replacements = @()
foreach ($Entry in @(
    @("/opt/die-source/Detect-It-Easy/db_custom", "Detect-It-Easy/db_custom"),
    @("/opt/die-source/Detect-It-Easy/db_extra", "Detect-It-Easy/db_extra"),
    @("/opt/die-source/Detect-It-Easy/db", "Detect-It-Easy/db")
)) {
    $From = $Entry[0]
    $To = $Entry[1]
    $Count = (
        $AdaptedSource.Length -
        $AdaptedSource.Replace($From, "").Length
    ) / $From.Length
    if ($Count -ne 1) {
        throw "Database path occurrence differs: $From ($Count)"
    }
    $AdaptedSource = $AdaptedSource.Replace($From, $To)
    $Replacements += [ordered]@{
        from = $From
        to = $To
        count = $Count
    }
}

$LocalHarness = Join-Path $ConsoleBuild `
    "archive_iteration_boundary_harness_main.cpp"
$HarnessMakefile = Join-Path $ConsoleBuild `
    "Makefile.ArchiveIteration.Release"
[System.IO.File]::WriteAllText(
    $LocalHarness,
    $AdaptedSource,
    [System.Text.UTF8Encoding]::new($false)
)
[System.IO.File]::WriteAllText(
    $HarnessMakefile,
    $PatchedMakefile,
    [System.Text.UTF8Encoding]::new($false)
)
$HarnessObject = Join-Path $ConsoleBuild $HarnessObjectName
$BuiltHarness = Join-Path $ConsoleBuild $HarnessTarget
foreach ($GeneratedPath in @($HarnessObject, $BuiltHarness)) {
    if (Test-Path -LiteralPath $GeneratedPath) {
        Remove-Item -LiteralPath $GeneratedPath -Force
    }
}

$Timer = [System.Diagnostics.Stopwatch]::StartNew()
$BuildCommand = @(
    "call `"$VsDevCmd`" -arch=amd64 -host_arch=amd64",
    "cd /d `"$ConsoleBuild`"",
    "nmake /NOLOGO /F Makefile.ArchiveIteration.Release $HarnessTarget"
) -join " && "
& $env:ComSpec /d /c $BuildCommand
if ($LASTEXITCODE -ne 0) {
    throw "archive-iteration harness build failed: $LASTEXITCODE"
}
$Timer.Stop()
$BuiltHarness = Resolve-ExistingPath $BuiltHarness "built harness"
$OutputParent = Split-Path -Parent $OutputBinary
if ($OutputParent -and -not (Test-Path -LiteralPath $OutputParent)) {
    New-Item -ItemType Directory -Path $OutputParent | Out-Null
}
[System.IO.File]::Copy($BuiltHarness, $OutputBinary, $true)
$OutputBinary = Resolve-ExistingPath $OutputBinary "output harness"

$Manifest = [ordered]@{
    schema_version = 1
    baseline = [ordered]@{
        repository = "https://github.com/horsicq/DIE-engine"
        commit = $ExpectedCommit
        rules_commit = $ExpectedRulesCommit
        recursive_submodule_count = $ExpectedSubmoduleCount
        cli_sha256 = $ExpectedCliSha256
    }
    qt = [ordered]@{
        version = "5.15.2"
        qmake_spec = "win32-msvc"
        qmake_sha256 = $ExpectedQmakeSha256
        qt5core_sha256 = $ExpectedQtCoreSha256
        qt5script_sha256 = $ExpectedQtScriptSha256
    }
    build = [ordered]@{
        system = "patched-qmake-release-makefile"
        tool = "nmake"
        target_architecture = "amd64"
        host_architecture = "amd64"
        original_makefile_sha256 = $ExpectedMakefileSha256
        original_main_object_sha256 = $ExpectedMainObjectSha256
        replaced_object = "release/main_console.obj"
        engine_objects_modified = $false
        platform_adaptation = [ordered]@{
            kind = "harness-only-peak-rss"
            unix_api = "getrusage(RUSAGE_SELF)"
            windows_api = "GetProcessMemoryInfo"
            engine_semantics_changed = $false
        }
        database_root = "<working-directory>/Detect-It-Easy"
        runtime_working_directory_contract = "verified-source-root"
        elapsed_milliseconds = $Timer.ElapsedMilliseconds
    }
    source_hashes = [ordered]@{
        builder = Get-Sha256 $MyInvocation.MyCommand.Path
        harness = [ordered]@{
            path = (
                "tools/upstream/" +
                "archive_iteration_boundary_harness_main.cpp"
            )
            original_sha256 = $ExpectedHarnessSha256
            adapted_sha256 = Get-Sha256 $LocalHarness
            database_path_replacements = $Replacements
        }
    }
    artifact = [ordered]@{
        filename = [System.IO.Path]::GetFileName($OutputBinary)
        size = (Get-Item -LiteralPath $OutputBinary).Length
        sha256 = Get-Sha256 $OutputBinary
    }
}

$Json = $Manifest | ConvertTo-Json -Depth 10
if ($OutputJson) {
    $JsonParent = Split-Path -Parent $OutputJson
    if ($JsonParent -and -not (Test-Path -LiteralPath $JsonParent)) {
        New-Item -ItemType Directory -Path $JsonParent | Out-Null
    }
    [System.IO.File]::WriteAllText(
        $OutputJson,
        $Json + [Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false)
    )
}
$Json
