using System.Management.Automation;
using TurtleToolKitImpersonate;


// [System.Security.Principal.windowsidentity]::GetCurrent() <- get token
namespace TurtleToolKit
{
    [Cmdlet(VerbsCommon.Get, "System")] // <- seeting cmdlet name and verbs
    [Alias("GSIT")] //<- cmdlet alias
    public class GetSystemImpersonationToken : Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            if (Impersonator.ElevateToSystem() != 0)
            {
                WriteWarning("Failed to impersonate system token");
                return;
            }
            WriteVerbose("Successfully impersonated system token");
            return;
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

    }
}

