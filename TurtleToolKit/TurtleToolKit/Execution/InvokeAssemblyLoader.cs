using System.Management.Automation;
using System;
using System.Reflection;

// [System.Security.Principal.windowsidentity]::GetCurrent() <- get token
namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "AssemblyLoader")] // <- seeting cmdlet name and verbs
    [Alias("IVNASM")] //<- cmdlet alias
    public class InvokeAssemblyLoader : Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            LoadAssemblyDll();
            return;
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        public bool LoadAssemblyDll()
        {
            try
            {
                var a = Assembly.LoadFile(@"C:\users\public\Tester.dll");
                var t = a.GetType("TesterNameSpace.TesterClass");
                var c = Activator.CreateInstance(t);
                var m = t.GetMethod("TesterMethod");
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