param (
    [string]$tetragonBinariesZip, # Path to the first ZIP archive
    [string]$ntosebpfextZip  # Path to the second ZIP archive
)

# Function to extract a zip file
function Extract-ZipFile {
    param (
        [string]$zipPath
    )
    $destinationName =  [System.IO.Path]::GetFileNameWithoutExtension($zipPath)
    $destinationPath = Join-Path (Split-Path -Parent $zipPath)$destinationName

    if ( (Test-Path $destinationPath)) {
        Remove-Item -Path $destinationPath -Recurse -Force
    }

    New-Item -ItemType Directory -Path $destinationPath
    
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $destinationPath)
}

$buildZip = $ntosebpfextZip
Write-Host "Extracting $buildZip"
$ntosebpfextZipBinaries = Extract-ZipFile -zipPath $buildZip
Write-Host "Ntosebpfext archive extracted to: $ntosebpfextZipBinaries"

$tetragonZip = $tetragonBinariesZip
Write-Host "Extracting $tetragonZip"
$tetragonBinaries = Extract-ZipFile -zipPath $tetragonZip
Write-Host "Tetragon archive extracted to: $tetragonBinaries"


New-Item -ItemType Directory -Path "C:\Program Files\Tetragon\cmd" -Force
New-Item -ItemType Directory -Path "C:\Program Files\Tetragon\BPF" -Force
New-Item -ItemType Directory -Path "C:\Program Files\Tetragon\tetragon.tp.d" -Force

Copy-Item -Path $tetragonBinaries\*.exe -destination "C:\Program Files\tetragon\cmd\" -Force

Copy-Item -Path "$ntosebpfextZipBinaries\Release\process_monitor_km\process_monitor.sys" -destination "C:\Program Files\tetragon\BPF\" -Force


Start-Process -FilePath "$ntosebpfextZipBinaries\Release\ntos_ebpf_ext_export_program_info.exe" -ArgumentList "--clear" -Wait

Start-Process -FilePath "$ntosebpfextZipBinaries\Release\ntos_ebpf_ext_export_program_info.exe" -Wait

sc.exe delete "ntosebpfext"

sc.exe create ntosebpfext type= kernel start= demand binPath= "$ntosebpfextZipBinaries\Release\ntosebpfext\ntosebpfext.sys"

sc.exe start ntosebpfext
