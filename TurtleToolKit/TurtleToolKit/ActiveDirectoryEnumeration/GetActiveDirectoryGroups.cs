using System.Management.Automation;
using TurtleToolKitAD;


namespace TurtleToolKit
{
    [Cmdlet(VerbsCommon.Get, "ActiveDirectoryGroups")] // <- seeting cmdlet name and verbs
    [Alias("GADGRPS")] //<- cmdlet alias
    public class GetActiveDirectoryGroups : Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            ActiveDirectory.ListGroups();
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

    }
}
