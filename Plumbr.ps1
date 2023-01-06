Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class WinApi{
// get proc address
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true)]
public static extern IntPtr GetProcAddress(
    IntPtr hModule,
    string procName
);

// get module handle.
[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
public static extern IntPtr GetModuleHandle(string lpModuleName);

// open process
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr OpenProcess(
 uint processAccess,
 bool bInheritHandle,
 int processId);

// virtual alloc ex 
[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
public static extern IntPtr VirtualAllocEx(
    IntPtr hProcess, 
    IntPtr lpAddress,
    uint dwSize,
    uint flAllocationType,
    uint flProtect);

// write process memory
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool WriteProcessMemory(
    IntPtr hProcess,
    IntPtr lpBaseAddress,
    byte[] lpBuffer,
    Int32 nSize,
    out IntPtr lpNumberOfBytesWritten);


//CreateRemoteThread
[DllImport("kernel32.dll")]
public static extern IntPtr CreateRemoteThread(
    IntPtr hProcess,
    IntPtr lpThreadAttributes,
    uint dwStackSize,
    IntPtr lpStartAddress,
    IntPtr lpParameter,
    uint dwCreationFlags,
    IntPtr lpThreadId);

// close handle
[DllImport("kernel32")]
public static extern Int32 CloseHandle(IntPtr hObject);

// free library
[DllImport("kernel32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
static extern bool FreeLibrary(IntPtr hModule);

// messageboxa testinng
[DllImport("user32.dll", CharSet = CharSet.Auto)]
public static extern int MessageBox(
    IntPtr hWnd,
    String text, 
    String caption, 
    int options);

//WaitForSingleObject
[DllImport("kernel32.dll")]
public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

// IntPtr output
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool GetExitCodeThread(IntPtr hThread, out IntPtr lpExitCode);

[DllImport("kernel32.dll")]
public static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);


[DllImport("kernel32.dll")]
public static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);


[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

public static uint Module = 0x00000008;
public static uint TH32CS_SNAPMODULE   = 0x00000008;

public static IntPtr GetRemoteModuleHandle(uint pid, ref string module) {
    var modEntry = new MODULEENTRY32();
    var tlh = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    modEntry.dwSize = (uint)Marshal.SizeOf(modEntry);
    Module32First(tlh, ref modEntry);
    do {
        if (string.Equals(modEntry.szModule, module, StringComparison.InvariantCultureIgnoreCase)) {
            return modEntry.hModule;
        }
        modEntry.dwSize = (uint)Marshal.SizeOf(modEntry);
    }
    while (Module32Next(tlh, ref modEntry));
    return IntPtr.Zero;
}

[StructLayout(LayoutKind.Sequential)]
public struct MODULEENTRY32 {
    public uint dwSize;
    public uint th32ModuleID;
    public uint th32ProcessID;
    public uint GlblcntUsage;
    public uint ProccntUsage;
    IntPtr modBaseAddr;
    public uint modBaseSize;
    public IntPtr hModule;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string szModule;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string szExePath;
}

public static uint AllAccess = 0x001F0FFF;
public static uint PAGE_READWRITE = 0x00000004;
public static uint PAGE_EXECUTE_READWRITE = 0x00000040;
}
"@

#region help
<#
.SYNOPSIS
View data a process has written and read from named pipes.

.DESCRIPTION
Injects Dll into process that hooks read/write File and writes pipe data to log file.

.PARAMETER pid
pid of the process to hook

.EXAMPLE
Invoke-Plumbing -pid 123

.EXAMPLE
Invoke-Plumbing -pid 123 -Verbose

.INPUTS
int

InputObject parameters are ints

.OUTPUTS
bool

.NOTES
FunctionName : Invoke-Plumbing
Created by   : Latortuga0x71
Date Coded   : 1/6/2023
More info    : https://latortuga.io/terminal

.LINK 
Out-File
#>
#endregion
function Invoke-Plumbing {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeLineByPropertyName=$true)]
        [Alias("pid","ProcessId")]
        [int]$p
    )
    $loadLibraryAddress = [WinApi]::GetProcAddress([WinApi]::GetModuleHandle("kernel32.dll"),"LoadLibraryA");
    if ($loadLibraryAddress -eq [IntPtr]::Zero) {
        Write-Error "[-] Failed to get load libary address";
        return;
    }
    Write-Verbose "[+] Got Address Of LoadLibraryA";
    $targetHandle = [WinApi]::OpenProcess(0x001F0FFF,$false,$p);
    if (!$targetHandle) {
        Write-Error "[-] Failed to get handle to target process";
        return;
    }
    Write-Verbose "[+] Successfully Opened Handle To ${p}";
    # alloc mem
    $dllPath = 'C:\Users\Christopher\source\repos\Plumbr\x64\Release\PlumbrDLL.dll';
    $dllPathBytes = [System.Text.Encoding]::Ascii.GetBytes($dllPath);
    $dllParameterAddress = [WinApi]::VirtualAllocEx($targetHandle, [IntPtr]::Zero, 4096, 0x3000, 0x04); # read write
    if ($dllParameterAddress -eq [IntPtr]::Zero) {
        Write-Error "[-] Failed to alloc memory";
        return;
    }
    ### Verbose ###
    if ([System.IntPtr]::Size -eq 4) {
        Write-Verbose "[+] Successfully Allocated Memory 0x$("{0:X8}" -f $dllParameterAddress.ToInt32())";
        } 
    else {
        Write-Verbose "[+] Successfully Allocated Memory 0x$("{0:X8}" -f $dllParameterAddress.ToInt64())";
    }
    $wrote = [IntPtr]::Zero;
    $worked = [WinApi]::WriteProcessMemory($targetHandle, $dllParameterAddress, $dllPathBytes, $dllPathBytes.Length, [ref] $wrote);
    if (!$worked){
        Write-Error "[-] Failed to write memory";
        return;
    }
    if ($wrote -eq 0) {
        Write-Error "[-] Failed to write memory";
        return;
    }
    Write-Verbose "[+] Successfully Wrote Memory";
    $dllThreadHandle = [WinApi]::CreateRemoteThread($targetHandle,0,0,$loadLibraryAddress,$dllParameterAddress,0,0)
    if (!$dllThreadHandle){
        Write-Error "[-] Failed to create remote thread";
        return;
    }
    Write-Verbose "[+] Successfully Injected Hooks Into Process.";    
    [WinApi]::CloseHandle($dllThreadHandle);
    [WinApi]::CloseHandle($targetHandle);
}



#region help
<#
.SYNOPSIS
Removes hooks from porcess

.DESCRIPTION
Unloads dll from process, removing the hooks

.PARAMETER pid
pid of the process to unhook

.EXAMPLE
Revoke-Plumbing -pid 123

.EXAMPLE
Revoke-Plumbing -pid 123 -Verbose

.INPUTS
int

InputObject parameters are ints

.OUTPUTS
bool

.NOTES
FunctionName : Revoke-Plumbing
Created by   : Latortuga0x71
Date Coded   : 1/6/2023
More info    : https://latortuga.io/terminal

.LINK 
Out-File
#>
#endregion
function Revoke-Plumbing {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeLineByPropertyName=$true)]
        [Alias("pid","ProcessId")]
        [int]$p
    )
    Write-Host "[+] Attempting to remove hooks.";
    $freeLibraryAddress = [WinApi]::GetProcAddress([WinApi]::GetModuleHandle("kernel32.dll"),"FreeLibrary");    
    if ($freeLibraryAddress -eq [IntPtr]::Zero) {
        Write-Error "[-] Failed to get free libary address";
        return;
    }
    Write-Verbose "[+] Got Address Of Free Library";
    $targetHandle = [WinApi]::OpenProcess(0x001F0FFF,$false,$p);
    if (!$targetHandle) {
        Write-Error "[-] Failed to get handle to target process";
        return;
    }
    Write-Verbose "[+] Opened process handle.";
    $handleToDLL = [WinApi]::GetRemoteModuleHandle($p,[ref] "PlumbrDLL.dll");
    if (!$handleToDLL) {
        Write-Error "[-] Failed to get handle to injected dll.";
        return;
    }
    Write-Verbose "[+] Got handle to injected dll";
    $thread = [WinApi]::CreateRemoteThread($targetHandle,[IntPtr]::Zero,0,$freeLibraryAddress,$handleToDLL,0,0)
    if (!$thread){
        Write-Error "[-] Failed to create remote thread";
        return;
    }
    Write-Host "[+] Freed Hooks."
}


#region help
<#
.SYNOPSIS
Reads pipe data from log file.

.DESCRIPTION
Reads data that hooked process is writing to tmp file.

.PARAMETER pid
pid of the process to watch

.EXAMPLE
Watch-Pipes -pid 123

.EXAMPLE
Watch-Pipes -pid 123 -Verbose

.INPUTS
int

InputObject parameters are ints

.OUTPUTS
bool

.NOTES
FunctionName : Watch-Pipes
Created by   : Latortuga0x71
Date Coded   : 1/6/2023
More info    : https://latortuga.io/terminal

.LINK 
Out-File
#>
#endregion
function Watch-Pipes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeLineByPropertyName=$true)]
        [Alias("pid","ProcessId")]
        [int]$p
    )
    if (!(Test-Path -Path "${env:TEMP}\PLUMBER.${p}.LOG" -PathType Leaf)){
        Write-Error "[-] Log file not found. Did you hook?";
        return $false;
    }
    Write-Verbose "[+] Log File Found...Tailing Log File.";
    try {
        Start-Sleep -Seconds 1
        Write-Host "[+] Ctrl-C to exit...";
        Get-Content "${env:TEMP}\PLUMBER.${p}.LOG" -wait | Format-Hex
    } finally {
        Write-Verbose "[+] Stopping Tail. Remember to free hooks.";
    }
    return $true;
}

