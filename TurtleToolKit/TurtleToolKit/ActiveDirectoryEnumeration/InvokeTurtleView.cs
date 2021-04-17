using System;
using System.Management.Automation;
using System.Reflection;
using TurtleToolKitCrypt;


namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "TurtleView")] // <- seeting cmdlet name and verbs
    [Alias("INVVIEW")] //<- cmdlet alias
    public class InvokeTurtleView: Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("c")] public string command { get; set; }

        private Cryptor cryptObj;

        protected override void BeginProcessing(){base.BeginProcessing();}

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            WriteVerbose("Command split by whitespace");
            //WriteWarning("DO NOT USE -help in commands, it will crash the process");
            base.ProcessRecord();
            if (ExecuteView())
            {
                WriteVerbose("Successfully executed");
                return;
            }
            WriteWarning("Failed to execute");
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        public bool ExecuteView()
        {
            try
            {
                cryptObj = new Cryptor(TurtleView.key, TurtleView.iv);
                var decryptedBytes = cryptObj.DecryptBytes(TurtleView.encryptedPayload);
                if (decryptedBytes == null)
                {
                    this.WriteWarning("Failed to decrypt bytes");
                    return false;
                }
                var ass = Assembly.Load(decryptedBytes);
                var t = ass.GetType("SharpView.Program");
                var c = Activator.CreateInstance(t);
                var m = t.GetMethod("Run");
                object[] paramz = new object[] { command.Split(' ') };
                m.Invoke(c, paramz);
                return true;
            }
            catch (Exception e)
            {
                throw e;
            }
            return true;
        }
    }
}
