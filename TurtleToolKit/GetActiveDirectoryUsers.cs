using System.Management.Automation;
using TurtleToolKitAD;

namespace TurtleToolKit
{
    [Cmdlet(VerbsCommon.Get, "ActiveDirectoryUsers")] // <- seeting cmdlet name and verbs
    [Alias("GADUSR")] //<- cmdlet alias
    public class GetActiveDirectoryUsers : Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            ActiveDirectory.ListUsers();
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

    }
}
