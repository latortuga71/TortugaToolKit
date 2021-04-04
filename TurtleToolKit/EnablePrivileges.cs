using System.Management.Automation;
using TurtleToolKitImpersonate;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Enable, "Privileges")] // <- seeting cmdlet name and verbs
    [Alias("EPRIVS")] //<- cmdlet alias
    public class EnablePrivileges : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("p")] public string privilege { get; set; }
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            if (!Impersonator.EnablePrivilege(privilege)){
                WriteWarning("Failed to enable privilege");
                return;
            }

            if (!Impersonator.IsPrivilegeEnabled(privilege))
            {
                WriteWarning("Failed to enable privilege");
                return;
            }
            WriteVerbose("Successfully enabled privilege");
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

    }
}