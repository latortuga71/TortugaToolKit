using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using System.Reflection;

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
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            LoadBloodHound();
            //testFunc2();
            return;
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        public bool testFunc2() {
            this.WriteObject("test");
            return true;
        }
        public bool LoadBloodHound()
        {
            try
            {
                var a = Assembly.LoadFile(@"C:\Users\Public\SharpHound.exe");
                var t = a.GetType("SharpHound3.SharpHound");
                var c = Activator.CreateInstance(t);
                var m = t.GetMethod("TurtleHound");
                m.Invoke(c, null);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }
    }

}