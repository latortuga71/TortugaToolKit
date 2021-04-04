using System.Management.Automation;
using TurtleToolKitImpersonate;

namespace TurtleToolKit
{
    [Cmdlet(VerbsSecurity.Revoke, "Privs")] // <- seeting cmdlet name and verbs
    [Alias("RVPRVS")] //<- cmdlet alias
    public class RevokePrivs: Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            if (!Impersonator.RevokePrivs())
            {
                WriteWarning("Failed to revert to self");
                return;
            }
            WriteVerbose("Successfully reverted to self");
            return;
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

    }
}
