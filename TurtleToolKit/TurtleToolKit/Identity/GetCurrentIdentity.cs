using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Principal;
using System.Management.Automation;

namespace TurtleToolKit
{
    [Cmdlet(VerbsCommon.Get, "CurrentIdentity")] // <- seeting cmdlet name and verbs
    [Alias("GETCI")] //<- cmdlet alias
    public class GetCurrentIdentity : Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            ExecuteGetCurrentIdentity();
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        public static bool ExecuteGetCurrentIdentity()
        {
            WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent();
            Console.WriteLine("The current user is : " + currentIdentity.Name);
            TokenImpersonationLevel token = currentIdentity.ImpersonationLevel;
            Console.WriteLine("The impersonation level for the current user is : " + token.ToString());
            var groups = currentIdentity.Groups.Translate(typeof(NTAccount));
            Console.WriteLine("The group memberships: ");
            Console.WriteLine("####################");
            foreach (var grp in groups)
            {
                Console.WriteLine(" ::: {0} :::",grp.Value);
            }
            return true;
        }

    }
}


/*
 * 
 * 
 
         static void Main(string[] args)
        {
            WindowsIdentity test = WindowsIdentity.GetCurrent();
            Console.WriteLine(test.Name);
            Console.WriteLine(test.ImpersonationLevel.ToString());
        }
    }
 */