using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using TurtleToolKitServices;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "AdminCheck")] // <- seeting cmdlet name and verbs
    [Alias("INVACHK")] //<- cmdlet alias
    public class InvokeAdminCheck : Cmdlet
    {
        [Parameter(Mandatory = false)] [Alias("t")] public string targetHost { get; set; }
        [Parameter(Mandatory = false)] [Alias("h")] public string[] hosts { get; set; }

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            // if no params specified
            if (string.IsNullOrEmpty(targetHost) && hosts.Length == 0)
            {
                WriteWarning("You must pass a (string)targetHost or (string array)hosts as a parameter");
                return;
            }
            // if targethost is set just check that one host
            if (!string.IsNullOrEmpty(targetHost))
            {
                if (!ExecuteAdminCheck(targetHost))
                {
                    WriteWarning("(-) NOT Admin on " + targetHost);
                    return;
                }
                WriteWarning("(+) YES Admin on " + targetHost);
                return;
            }
            // if hostFile is set take list of users and 
            foreach(string host in hosts)
            {
                if (!ExecuteAdminCheck(host))
                {
                    WriteWarning("(-) NOT Admin on " + host);
                    continue;
                }
                WriteWarning("(+) YES Admin on " + host);
                continue;
            }
            return;
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }
        public static bool ExecuteAdminCheck(string targetHost)
        {
            if (!Services.CheckIfAdminAccess(targetHost))
                return false;
            return true;
        }

    }
}
