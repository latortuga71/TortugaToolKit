using System;
using TurtleToolKitImpersonate;
using TurtleToolKitOutputs;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke,"ImpersonateToken")]
    [Alias("INVTOKEN")] //<- cmdlet alias
    public class ImpersonateToken : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("pid")] public int processId { get; set; }
        SuccessObject success = new SuccessObject { Success = false };

        protected override void BeginProcessing(){
            base.BeginProcessing();
        }
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            if (ImpersonateUserViaToken(processId))
            {
                WriteVerbose("Success");
                success.Success = true;
                return;
            }
            WriteWarning("Failed");
        }
        protected override void EndProcessing() {
            WriteObject(success);
        }
        protected override void StopProcessing() { 
            base.StopProcessing(); 
        }
        public static bool ImpersonateUserViaToken(int pid)
        {
            if (Impersonator.ElevateToSystem() != 0)
            {
                Console.WriteLine("Failed to get system before impersonating user");
                return false;
            }
            if (!Impersonator.ImpersonateLoggedOnUserViaToken(pid))

            {
                Console.WriteLine("err failed impersonate logged on user VIA TOKEN {0}", Marshal.GetLastWin32Error());
                Impersonator.RevokePrivs();
                return false;
            }
            return true;
        }
    }
}