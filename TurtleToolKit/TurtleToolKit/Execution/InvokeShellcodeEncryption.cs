using System;
using System.Management.Automation;
using TurtleToolKitCrypt;
using TurtleToolKitOutputs;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "SCEncryption")] // <- seeting cmdlet name and verbs
    [OutputType(typeof(ShellCodeEncryptedOutput))]       // <-- setting output type
    [Alias("ISENC")] //<- cmdlet alias
    public class InvokeShellcodeEncryption : Cmdlet
    {
        [Parameter(Mandatory = true)]
        [Alias("s")] //<- parameter alias
        public byte[] shellCode { get; set; }

        // set class variables
        private Cryptor cryptObj;
        private byte[] i = new byte[16]; // { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        private byte[] k = new byte[16];

        // Init cmdlet
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            // create random key
            Random rnd = new Random();
            rnd.NextBytes(k);
            Random rnd2 = new Random();
            rnd2.NextBytes(i);
            // create new cryptObj
            cryptObj = new Cryptor(k, i);
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            byte[] encryptedShellcode = cryptObj.EncryptBytes(shellCode);
            ShellCodeEncryptedOutput output = new ShellCodeEncryptedOutput();
            if (encryptedShellcode == null)
            {
                WriteWarning("Failed to encrypt shellcode");
                WriteObject(null);
            }
            WriteVerbose("Successfully encrypted shellcode");
            output.encryptedShellcode = encryptedShellcode;
            output.encryptionKey = k;
            output.initVectorKey = i;
            WriteObject(output);
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }
    }
}

   

    
