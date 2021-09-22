using System;
using System.Management.Automation;
using System.IO;
using System.Runtime.InteropServices;
using TurtleToolKitManaged;
using PeHeaderParser;
using TurtleToolKitOutputs;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke,"UnhookDll")]
    [Alias("unhk")]
    public class UnhookDll : Cmdlet
    {
        [Parameter(Mandatory = false)]
        [Alias("d")] //public string dll { get; set; }
        public string dll = "C:\\windows\\system32\\ntdll.dll";
        [Parameter(Mandatory = false)]
        [Alias("p")] //public string dll { get; set; }
        public int pid = 0;

        public static SuccessObject success;

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            WriteVerbose(dll);
            success = new SuccessObject { Success = false };
        }
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            // in future accept file objects like from get-childItem
            WriteVerbose("Only works on 64bit");
            if (UnhookAnyDll(pid,dll))
            {
                WriteVerbose("Success");
                success.Success = true;
            } else
            {
                WriteWarning("Failed");
            }

        }
        protected override void EndProcessing()
        {
            base.EndProcessing();
            WriteObject(success);
        }
        protected override void StopProcessing()
        {
            base.StopProcessing();
        }
        bool unHook(IntPtr hookedNtdllAddr, IntPtr cleanNtdllmapping,string pathToCleanDll)
        {
            uint oldProtect = 0;
            PeHeaderReader reader = new PeHeaderReader(pathToCleanDll);
            PeHeaderReader.IMAGE_SECTION_HEADER textSection = reader.ImageSectionHeaders[0];
            IntPtr offsetToTextSectionHooked = new IntPtr(hookedNtdllAddr.ToInt64() + textSection.VirtualAddress);
            IntPtr offsetToTextSectionClean = new IntPtr(cleanNtdllmapping.ToInt64() + textSection.VirtualAddress);
            // set memory protections to read write execute
            bool vProtResult = Win32.VirtualProtect(offsetToTextSectionHooked, (UIntPtr)textSection.VirtualSize, 0x40, out oldProtect);
            if (!vProtResult)
            {
                return false;
            }
            this.WriteVerbose("Changed memory protections to allow write");
            // read fresh text section
            byte[] cleanTextBytes = new byte[textSection.VirtualSize];
            IntPtr nRead = IntPtr.Zero;
            if (!Win32.ReadProcessMemory(Win32.GetCurrentProcess(), offsetToTextSectionClean, cleanTextBytes, (int)textSection.VirtualSize, out nRead))
            {
                this.WriteWarning("Failed to read memory");
                return false;
            }
            this.WriteVerbose("Read clean dll .text section into buffer");
            Marshal.Copy(cleanTextBytes, 0, offsetToTextSectionHooked, (int)textSection.VirtualSize);
            this.WriteVerbose("Copied Clean dll into hooked dll");
            vProtResult = Win32.VirtualProtect(offsetToTextSectionHooked, (UIntPtr)textSection.VirtualSize, oldProtect, out oldProtect);
            if (!vProtResult)
            {
                return false;
            }
            this.WriteVerbose("Reverted Memory Protections");
            return true;
        }
        bool unHookRemote(IntPtr remoteProcessHandle, IntPtr hookedNtdllAddr, IntPtr cleanNtdllmapping, string pathToCleanDll)
        {
            WriteVerbose("Remote unhook");
            uint oldProtect = 0;
            PeHeaderReader reader = new PeHeaderReader(pathToCleanDll);
            PeHeaderReader.IMAGE_SECTION_HEADER textSection = reader.ImageSectionHeaders[0];
            IntPtr offsetToTextSectionHooked = new IntPtr(hookedNtdllAddr.ToInt64() + textSection.VirtualAddress);
            IntPtr offsetToTextSectionClean = new IntPtr(cleanNtdllmapping.ToInt64() + textSection.VirtualAddress);
            // set memory protections to read write execute
            // Change memory protections on REMOTE process

            bool vProtResult = Win32.VirtualProtectEx(remoteProcessHandle,offsetToTextSectionHooked, (UIntPtr)textSection.VirtualSize, 0x40, out oldProtect);
            //bool vProtResult = Win32.VirtualProtect(offsetToTextSectionHooked, (UIntPtr)textSection.VirtualSize, 0x40, out oldProtect);
            if (!vProtResult)
            {
                return false;
            }
            this.WriteVerbose("Changed memory protections to allow write");
            // read fresh text section
            byte[] cleanTextBytes = new byte[textSection.VirtualSize];
            IntPtr nRead = IntPtr.Zero;
            IntPtr nWrote = IntPtr.Zero;
            if (!Win32.ReadProcessMemory(Win32.GetCurrentProcess(), offsetToTextSectionClean, cleanTextBytes, (int)textSection.VirtualSize, out nRead))
            {
                this.WriteWarning("Failed to read memory");
                return false;
            }
            this.WriteVerbose("Read clean dll .text section into buffer");
            //Marshal.Copy(cleanTextBytes, 0, offsetToTextSectionHooked, (int)textSection.VirtualSize);
            if (!Win32.WriteProcessMemory(remoteProcessHandle, offsetToTextSectionHooked, cleanTextBytes, (int)textSection.VirtualSize, out nWrote))
            {
                this.WriteWarning("Failed to write memory");
                return false;
            }
            this.WriteVerbose("Copied Clean dll into hooked dll");
            vProtResult = Win32.VirtualProtectEx(remoteProcessHandle, offsetToTextSectionHooked, (UIntPtr)textSection.VirtualSize, oldProtect, out oldProtect);
            if (!vProtResult)
            {
                return false;
            }
            this.WriteVerbose("Reverted Memory Protections");
            return true;
        }

        public bool UnhookAnyDll(int pid = 0, string pathToDll = "C:\\windows\\system32\\ntdll.dll")
        {
            this.WriteVerbose("Getting handle to clean dll");
            IntPtr hCleanNtdll = Win32.CreateFileA(pathToDll, FileAccess.Read, FileShare.Read, IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero);
            IntPtr hFileMapping = Win32.CreateFileMapping(hCleanNtdll, IntPtr.Zero, Win32.FileMapProtection.PageReadonly | Win32.FileMapProtection.SectionImage, 0, 0, "");
            IntPtr ptrMapping = Win32.MapViewOfFileEx(hFileMapping, Win32.FileMapAccessType.Read, 0, 0, UIntPtr.Zero, IntPtr.Zero);
            if (ptrMapping == IntPtr.Zero)
            {
                this.WriteWarning("Failed to map view of file");
            }
            string[] moduleNameSplit = pathToDll.Split('\\');
            string moduleName = "";
            foreach(string n in moduleNameSplit)
            {
                if (n.EndsWith(".dll"))
                {
                    moduleName = n;
                    this.WriteVerbose("Got module name : " + moduleName);
                    break;
                }
            }
            if (moduleName == "")
            {
                this.WriteWarning("Failed to split module name");
                return false;
            }
            IntPtr addressOfHookedNtdll = Win32.GetModuleHandle(pathToDll);
            Win32.CloseHandle(hFileMapping);
            Win32.CloseHandle(hCleanNtdll);
            if (pid != 0)
            {
                // call unhook remote
                IntPtr hrProcess = Win32.OpenProcess(0x001F0FFF, false, pid);
                if (!unHookRemote(hrProcess,addressOfHookedNtdll, ptrMapping, pathToDll)){
                    return false;
                }
                return true;
            } 
            // call local unhook
            if (!unHook(addressOfHookedNtdll, ptrMapping, pathToDll))
            {
                this.WriteWarning("Failed!");
                Win32.UnmapViewOfFile(ptrMapping);
                return false;
            }
            Win32.UnmapViewOfFile(ptrMapping);
            return true;
        }
    }
}
