using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;

// [System.Security.Principal.windowsidentity]::GetCurrent() <- get token
namespace TurtleToolKit
{
    [Cmdlet(VerbsCommon.Get, "TEST")] // <- seeting cmdlet name and verbs
    [Alias("GTEST")] //<- cmdlet alias
    public class GetTest : Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            //WriteInformation(new HostInformationMessage { Message = "Hellow from c#", ForegroundColor = ConsoleColor.Green, NoNewLine = false }, new[] { "PSHOST" });
            testFunc();
            testFunc2();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();

            return;
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        protected bool testFunc()
        {
            WriteInformation(new HostInformationMessage { Message = "Hellow from c#", ForegroundColor = ConsoleColor.Green, NoNewLine = false }, new[] { "PSHOST" });
            return true;
        }
        public bool testFunc2()
        {
            this.WriteInformation(new HostInformationMessage { Message = "Hellow from c# PT.2", ForegroundColor = ConsoleColor.Green, NoNewLine = false }, new[] { "PSHOST" });
            return true;
        }

    }

}