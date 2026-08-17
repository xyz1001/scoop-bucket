[CmdletBinding()]
param(
    [switch]$PrerequisitesConfirmed
)

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Confirm-DefendNotPrerequisites {
    Write-Host ''
    Write-Host 'Upstream DefendNot advises disabling Windows Defender Real-time protection and Smart App Control.'
    Write-Host 'First, disable Real-time protection in the Windows Security page that will open now.'
    try {
        Start-Process -FilePath 'windowsdefender://threatsettings/' | Out-Null
    }
    catch {
        throw ('Unable to open the Windows Defender threat settings page: ' + $_.Exception.Message)
    }

    [void](Read-Host 'After disabling Real-time protection, press Enter to continue')

    Write-Host 'Now review and disable Smart App Control in the Windows Security page that will open.'
    try {
        Start-Process -FilePath 'windowsdefender://appbrowser/' | Out-Null
    }
    catch {
        throw ('Unable to open the Windows Defender App & browser control page: ' + $_.Exception.Message)
    }

    [void](Read-Host 'After reviewing or disabling Smart App Control, press Enter to continue')
}

function Resolve-DefendNotLoader {
    param(
        [Parameter(Mandatory = $true)]
        $ScoopCommand
    )

    $prefixOutput = @(& $ScoopCommand.Name prefix defendnot 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'Scoop could not resolve the installed defendnot package.'
    }

    $prefixLines = @($prefixOutput | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ })
    if ($prefixLines.Count -eq 0) {
        throw 'Scoop returned an empty installation path for defendnot.'
    }
    $packageDirectory = $prefixLines[$prefixLines.Count - 1]
    if (-not (Test-Path -LiteralPath $packageDirectory -PathType Container)) {
        throw ('Scoop reported a package directory that does not exist: ' + $packageDirectory)
    }

    $loaderMatches = @(Get-ChildItem -LiteralPath $packageDirectory -Filter 'defendnot-loader.exe' -File -Recurse)
    if ($loaderMatches.Count -ne 1) {
        throw ('Expected exactly one defendnot-loader.exe under ' + $packageDirectory + ', found ' + $loaderMatches.Count + '.')
    }

    $loaderPath = $loaderMatches[0].FullName
    if (-not (Test-Path -LiteralPath $loaderPath -PathType Leaf)) {
        throw ('The DefendNot loader does not exist: ' + $loaderPath)
    }
    return $loaderPath
}

if (-not $PrerequisitesConfirmed) {
    try {
        Confirm-DefendNotPrerequisites
    }
    catch {
        Write-Error ('DefendNot preparation failed: ' + $_.Exception.Message)
        exit 1
    }
}

if (-not (Test-IsAdministrator)) {
    Write-Host 'Administrator permission is required. Requesting elevation...'
    try {
        $currentHostPath = (Get-Process -Id $PID -ErrorAction Stop).Path
        if ([string]::IsNullOrWhiteSpace($currentHostPath)) {
            throw 'The current PowerShell host executable path could not be determined.'
        }
        $arguments = @(
            '-NoProfile'
            '-ExecutionPolicy Bypass'
            ('-File "' + $PSCommandPath + '"')
            '-PrerequisitesConfirmed'
        )
        $elevated = Start-Process -FilePath $currentHostPath `
            -ArgumentList $arguments -Verb RunAs -Wait -PassThru
        exit $elevated.ExitCode
    }
    catch {
        Write-Error ('Unable to obtain Administrator permission: ' + $_.Exception.Message)
        exit 1
    }
}

try {
    Write-Host 'Locating the Scoop-installed DefendNot package...'
    $scoopCommand = Get-Command scoop -ErrorAction Stop
    try {
        $loaderPath = Resolve-DefendNotLoader -ScoopCommand $scoopCommand
    }
    catch {
        Write-Warning ('The Scoop-installed DefendNot loader could not be found. It may have been quarantined by Defender. ' + $_.Exception.Message)
        Write-Host 'Attempting recovery with: scoop install defendnot'
        & $scoopCommand.Name install defendnot
        $installExitCode = $LASTEXITCODE
        if ($installExitCode -ne 0) {
            throw ('scoop install defendnot failed with exit code ' + $installExitCode + '.')
        }

        try {
            $loaderPath = Resolve-DefendNotLoader -ScoopCommand $scoopCommand
        }
        catch {
            throw ('The DefendNot loader is still unavailable after recovery: ' + $_.Exception.Message)
        }
    }

    $workingDirectory = Split-Path -Parent $loaderPath

    Write-Host ('Launching ' + $loaderPath + ' with its default behavior...')
    $loaderProcess = Start-Process -FilePath $loaderPath -WorkingDirectory $workingDirectory -Wait -PassThru
    Write-Host ('DefendNot finished with exit code ' + $loaderProcess.ExitCode + '.')
    if ($loaderProcess.ExitCode -ne 0) {
        exit $loaderProcess.ExitCode
    }

    $stripPath = Join-Path $workingDirectory 'extra-strip.bat'
    if (-not (Test-Path -LiteralPath $stripPath -PathType Leaf)) {
        throw ('DefendNot completed successfully, but extra-strip.bat was not found alongside the loader: ' + $stripPath)
    }

    Write-Host 'DefendNot completed successfully. Launching extra-strip.bat...'
    $stripProcess = Start-Process -FilePath $env:ComSpec `
        -ArgumentList @('/d', '/c', ('call "' + $stripPath + '"')) `
        -WorkingDirectory $workingDirectory -Wait -PassThru
    Write-Host ('extra-strip.bat finished with exit code ' + $stripProcess.ExitCode + '.')
    exit $stripProcess.ExitCode
}
catch {
    Write-Error ('Unable to launch the Scoop-installed DefendNot loader: ' + $_.Exception.Message)
    exit 1
}
