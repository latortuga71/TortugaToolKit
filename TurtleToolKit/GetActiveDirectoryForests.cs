using System.Management.Automation;
using TurtleToolKitAD;

namespace TurtleToolKit
{
    [Cmdlet(VerbsCommon.Get, "ActiveDirectoryForests")] // <- seeting cmdlet name and verbs
    [Alias("GADFRSTS")] //<- cmdlet alias
    public class GetActiveDirectoryForests : Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            ActiveDirectory.ListDomainsInForest();
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

    }
}
