using System.Management.Automation;
using TurtleToolKitAD;

namespace TurtleToolKit
{
    [Cmdlet(VerbsCommon.Get, "ActiveDirectoryGroupMembership")] // <- seeting cmdlet name and verbs
    [Alias("GADGRPMEM")] //<- cmdlet alias
    public class GetActiveDirectoryGroupMembership : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("u")] public string userName { get; set; }
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            ActiveDirectory.ListUserGroupMemberships(userName);
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

    }
}
