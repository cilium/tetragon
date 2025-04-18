# Windows Installation using powershell script

To setup tetragon.exe on Windows, follow these steps:

1. Install Ebpf-For-Windows version 0.21.0 msi available [here](https://github.com/microsoft/ebpf-for-windows/releases/download/Release-v0.21.0/ebpf-for-windows.x64.0.21.0.msi)
2. Download the tetragon.exe and ntosebpfext build artifacts produced as a result of "Windows Build and Smoke / Build and Uplod Windows Tetragon and Tetra Binaries" CI workflow step 
3. Unpack the downloaded archives and place the resulting `Tetragon-On-Windows.zip` and `build-x64.Release.zip` folders in the same parent folder
4. Launch powershell as admin and launch `setup-windows.ps1 <Path to Tetragon-On-Windows.zip> <Path to build-x64.Release.zip>`. This will install Tetragon.exe 
5. From an admin powershell or command prompt, launch `C:\Program Files\Tetragon\cmd\Tetragon.exe` and (separately) launch `C:\Program Files\Tetragon\cmd\Tetra.exe` to view exec and exit events. 
