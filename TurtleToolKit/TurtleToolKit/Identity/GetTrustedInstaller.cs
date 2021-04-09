using System.Management.Automation;
using TurtleToolKitImpersonate;
using TurtleToolKitServices;

namespace TurtleToolKit
{
    [Cmdlet(VerbsCommon.Get, "TrustedInstaller")] // <- seeting cmdlet name and verbs
    [Alias("GTSIT")] //<- cmdlet alias
    public class GetTrustedInstallerImpersonationToken : Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            if (Services.StartTrustedInstaller() != 0)
            {
                WriteWarning("Failed to start trusted installer");
                return;
            } 
            if (Impersonator.ElevateToTs() != 0)
            {
                WriteWarning("Failed to impersonate trustedinstaller token");
                return;
            }
            WriteVerbose("Successfully impersonated trustedinstaller token");
            return;
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

    }
}
