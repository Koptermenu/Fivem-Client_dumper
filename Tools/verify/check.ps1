<#
    One command, one verdict.

        powershell -NoProfile -ExecutionPolicy Bypass -File check.ps1

    Steps, in order:
      1. build verify\bin\pass.exe from the project's current cleanup sources
         (rebuilds only when a source is newer, which matters because the pass is
         edited in place while this runs)
      2. build the second corpus under verify\work\macho by decrypting every
         Macho directory that holds a .fxap, then running the pass over it
      3. run selfcheck.py, which proves the four historical failures are
         detectable; if it does not pass, the gate below proves nothing
      4. run gate.py over both corpora and exit non-zero if anything failed

    Nothing outside this directory is written to. The corpora are read only.
#>
[CmdletBinding()]
param(
    [switch]$SkipCorpusBuild,
    [switch]$SelfCheckOnly,
    [switch]$NoTiming,
    [int]$LimitSeconds = 30,
    [int]$Jobs = 8,
    [string]$YesRoot = '',
    [string]$MachoWork = ''
)

$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Py = 'python'
$Node = 'node'
$Pass = Join-Path $Here 'bin\pass.exe'
$Work = Join-Path $Here 'work'
if (-not $YesRoot) { $YesRoot = Join-Path $Work 'yes\Servers\yes' }
if (-not $MachoWork) { $MachoWork = Join-Path $Work 'macho' }
if (-not (Test-Path (Join-Path $YesRoot 'Output'))) {
    Write-Host "yes corpus not found at $YesRoot - pass -YesRoot <dir holding Output and Output_gate>"
    exit 2
}
$Logs = Join-Path $Work 'logs'
New-Item -ItemType Directory -Force -Path $Logs | Out-Null

function Say($msg) { Write-Host $msg }

function RunStep($name, $file, [string[]]$argList) {
    Say ''
    Say ('=' * 78)
    Say ("  $name")
    Say ('=' * 78)
    $stdout = Join-Path $Logs (($name -replace '[^A-Za-z0-9]', '_') + '.out')
    $stderr = $stdout + '.err'
    $p = Start-Process -FilePath $file -ArgumentList $argList -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    Get-Content $stdout -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
    $errText = Get-Content $stderr -Raw -ErrorAction SilentlyContinue
    if ($p.ExitCode -ne 0 -and $errText) { Write-Host $errText }
    return $p.ExitCode
}

Say ("verification gate   " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Say ("  gate dir          " + $Here)
Say ("  cleanup sources   C:\Users\Admin\Desktop\Dumper - AllInOne\src\ai\Cleanup.cpp")

# 1. the pass under test
Say ''
Say ('-' * 78)
Say '  step 1  build the cleanup pass from current sources'
Say ('-' * 78)
$build = Join-Path $Logs 'build_pass.out'
$p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ('"{0}"' -f (Join-Path $Here 'build_pass.bat')) `
    -NoNewWindow -Wait -PassThru -RedirectStandardOutput $build -RedirectStandardError ($build + '.err')
Get-Content $build -ErrorAction SilentlyContinue | Select-Object -Last 3 | ForEach-Object { Write-Host $_ }
if ($p.ExitCode -ne 0) {
    Write-Host ''
    Write-Host 'BUILD FAILED - cannot measure a pass that does not build'
    Get-Content ($build + '.err') -ErrorAction SilentlyContinue | Select-Object -Last 20 |
        ForEach-Object { Write-Host $_ }
    exit 2
}
if (-not (Test-Path $Pass)) { Write-Host 'BUILD FAILED - pass.exe missing'; exit 2 }
Say ("  pass.exe          " + $Pass)

# 2. the second corpus
if (-not $SkipCorpusBuild) {
    $macho = Join-Path $Here 'work\macho\index.json'
    $needBuild = $true
    if (Test-Path $macho) { $needBuild = $false }
    if ($needBuild) {
        $null = RunStep 'build second corpus' $Node @((Join-Path $Here 'build_macho_corpus.js'))
        if (-not (Test-Path $macho)) {
            Write-Host ''
            Write-Host 'second corpus could not be built; the gate will run on the first corpus only'
        }
    } else {
        Say '  second corpus already built (pass -SkipCorpusBuild to force a rebuild)'
    }
}

# 2b. run the pass over every corpus from the current sources.
#
# This step was missing, and it is why the gate spent the evening reporting failures that no
# longer reproduce: it built a fresh pass.exe and then compared Output against whatever
# Output_clean happened to be on disk, produced by an earlier build. It scored thirteen broken
# files and two hundred lost comments that had already been fixed. A gate that reads stale
# output is worse than no gate, because it is believed.
Say ''
Say ('-' * 78)
Say '  step 2b  run the cleanup pass over both corpora from the current source'
Say ('-' * 78)
$stale = 0
foreach ($corpus in @('yes', 'macho')) {
    $roots = @()
    if ($corpus -eq 'yes') {
        $roots += (Join-Path $YesRoot 'Output')
    } else {
        foreach ($d in (Get-ChildItem (Join-Path $Here 'work\macho') -Recurse -Directory -Filter 'Output' -ErrorAction SilentlyContinue)) {
            $roots += $d.FullName
        }
    }
    $n = 0
    foreach ($src in $roots) {
        $dst = $src -replace '\\Output$', '\Output_gate'
        if (Test-Path $dst) { Remove-Item $dst -Recurse -Force -ErrorAction SilentlyContinue }
        Push-Location (Split-Path $src -Parent)
        $null = & $Pass 'Output' 'Output_gate' 2>&1
        Pop-Location
        $n++
    }
    Say ("  ran pass over {0,-6} {1} root(s)" -f $corpus, $n)
}

# 3. selfcheck
Say ''
Say ('-' * 78)
Say '  step 3  selfcheck: the four historical failures must be detectable'
Say ('-' * 78)
$selfOut = Join-Path $Logs 'selfcheck.out'
$p = Start-Process -FilePath $Py -ArgumentList @('"{0}"' -f (Join-Path $Here 'selfcheck.py')) `
    -WorkingDirectory $Here -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $selfOut -RedirectStandardError ($selfOut + '.err')
Get-Content $selfOut -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
if ($p.ExitCode -ne 0) {
    Get-Content ($selfOut + '.err') -ErrorAction SilentlyContinue | Select-Object -Last 20 |
        ForEach-Object { Write-Host $_ }
    Write-Host ''
    Write-Host 'SELFCHECK FAILED - a check cannot detect a failure it has already shipped'
    exit 3
}
Say '  selfcheck: all four historical failures detected'

if ($SelfCheckOnly) { exit 0 }

# 4. the gate
$gateArgs = @(('"{0}"' -f (Join-Path $Here 'gate.py')), '--pass-exe', ('"{0}"' -f $Pass),
    '--yes-root', ('"{0}"' -f $YesRoot), '--macho-work', ('"{0}"' -f $MachoWork),
    '--json', ('"{0}"' -f (Join-Path $Work 'verdict.json')), '--limit', "$LimitSeconds", '--jobs', "$Jobs")
if ($NoTiming) { $gateArgs += '--no-timing' }
$gateExit = RunStep 'gate' $Py $gateArgs

Say ''
Say ('=' * 78)
if ($gateExit -eq 0) {
    Say '  VERDICT: PASS - the cleanup pass is safe and more readable'
} else {
    Say '  VERDICT: FAIL - see the FAIL lines above'
}
Say ('=' * 78)
Say ("  full report: " + (Join-Path $Work 'verdict.json'))
exit $gateExit