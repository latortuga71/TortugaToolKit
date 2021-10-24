using System.Management.Automation;
using TurtleToolKitImpersonate;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "RunAs")] // <- seeting cmdlet name and verbs
    [Alias("RUNAS")] //<- cmdlet alias
    public class InvokeRunAs : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("u")] public string Username { get; set; }
        [Parameter(Mandatory = true)] [Alias("p")] public string Password { get; set; }
        [Parameter(Mandatory = false)] [Alias("d")] public string Domain = ".";
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            if (!Impersonator.ImpersonateUserViaLogonCreds(Username, Password,Domain))
            {
                WriteWarning("Failed to run as " + Username);
                return;
            }
            WriteVerbose("Interactive Shell as " + Username);
            return;
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }


    }
}