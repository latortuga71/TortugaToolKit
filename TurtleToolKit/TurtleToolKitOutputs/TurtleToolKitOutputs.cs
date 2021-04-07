using System;

namespace TurtleToolKitOutputs
{
    public class ProcessHollowOutput
    {
        public string ProcName { get; set; }
        public int Procpid { get; set; }
        public int ReturnValue { get; set; }
    }
    public class ShellCodeEncryptedOutput
    {
       public byte[] encryptedShellcode { get; set; }
       public byte[] encryptionKey { get; set; }
       public byte[] initVectorKey { get; set; }
    }

     public class TokenObjects
    {
        public IntPtr processHandle;
        public IntPtr tokenHandle;
        public string userName;
        public string userDomain;
        public uint logonType;
        public string procName;
        public int pid;
    }
}
