using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using HANDLE = System.IntPtr;
using HPSS = System.IntPtr;
using PVOID = System.IntPtr;
using PMINIDUMP_CALLBACK_INPUT = System.IntPtr;
using PMINIDUMP_CALLBACK_OUTPUT = System.IntPtr;
using PMINIDUMP_EXCEPTION_INFORMATION = System.IntPtr;
using PMINIDUMP_USER_STREAM_INFORMATION = System.IntPtr;
using PMINIDUMP_CALLBACK_INFORMATION = System.IntPtr;
using BOOL = System.Int32;
using DWORD = System.Int32;

namespace TurtleToolKitManaged
{
    class Win32
    {
        /// <summary>
        ///  process and injection definitions
        /// </summary>
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniqueProcessId;
            public IntPtr MoreReserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr Thread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);


        //create process
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
       public static extern bool CreateProcess(
       string lpApplicationName,
       string lpCommandLine,
       IntPtr lpProcessAttributes,
       IntPtr lpThreadAttributes,
       bool bInheritHandles,
       uint dwCreationFlags,
       IntPtr lpEnvironment,
       string lpCurrentDirectory,
       [In] ref STARTUPINFO lpStartupInfo,
       out PROCESS_INFORMATION lpProcessInformation);

        //zw query information
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 ZwQueryInformationProcess(
        IntPtr hProcess,
        int procInformationClass,
        ref PROCESS_BASIC_INFORMATION procInformation,
        UInt32 ProcInfoLen,
        ref UInt32 retlen);


        // readprocessmemory
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead);

        // write process memory
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
          IntPtr hProcess,
          IntPtr lpBaseAddress,
          byte[] lpBuffer,
          Int32 nSize,
          out IntPtr lpNumberOfBytesWritten);

        /// resume thread
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(
            IntPtr hThread);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int MessageBox(
            IntPtr hWnd,
            String text, 
            String caption, 
            int options);

        [DllImport("kernel32.dll",SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpfOldProtect);


        //VirtualAlloc
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            uint dwSize, 
            uint flAllocationType, 
            uint flProtect);

        //CreateThread
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        //CreateRemoteThread
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        //WaitForSingleObject
        [DllImport("kernel32.dll")]
        public static extern UInt32 WaitForSingleObjectt(
            IntPtr hHandle, 
            UInt32 dwMilliseconds);


        // open process
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
         uint processAccess,
         bool bInheritHandle,
         int processId);

        // virtual alloc ex 
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess, 
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);


        ////
        /// impersonate functions definitions
        /// 
          // Constants that are going to be used during our procedure.
        private const int ANYSIZE_ARRAY = 1;
        public static uint SE_PRIVILEGE_ENABLED = 0x00000002;
        public static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public static uint STANDARD_RIGHTS_READ = 0x00020000;
        public static uint TOKEN_ASSIGN_PRIMARY = 0x00000001;
        public static uint TOKEN_DUPLICATE = 0x00000002;
        public static uint TOKEN_IMPERSONATE = 0x00000004;
        public static uint TOKEN_QUERY = 0x00000008;
        public static uint TOKEN_QUERY_SOURCE = 0x00000010;
        public static uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public static uint TOKEN_ADJUST_GROUPS = 0x00000040;
        public static uint TOKEN_ADJUST_DEFAULT = 0x00000080;
        public static uint TOKEN_ADJUST_SESSIONID = 0x00000100;
        public static uint TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY;
        public static uint TOKEN_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;

            public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
            public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
            public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
            public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;
        }

        // Luid Structure Definition
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;
        }

        public struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = ANYSIZE_ARRAY)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PRIVILEGE_SET
        {
            public uint PrivilegeCount;
            public uint Control;  // use PRIVILEGE_SET_ALL_NECESSARY

            public static uint PRIVILEGE_SET_ALL_NECESSARY = 1;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privilege;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }
        /// DEFINITIONS FOR MINIDUMP -> https://github.com/mjsabby/CopyOnWriteDump/blob/master/Program.cs great code
        ///     using DWORD = System.Int32;
        ///     

        public enum MINIDUMP_CALLBACK_TYPE : uint
        {
            ModuleCallback,
            ThreadCallback,
            ThreadExCallback,
            IncludeThreadCallback,
            IncludeModuleCallback,
            MemoryCallback,
            CancelCallback,
            WriteKernelMinidumpCallback,
            KernelMinidumpStatusCallback,
            RemoveMemoryCallback,
            IncludeVmRegionCallback,
            IoStartCallback,
            IoWriteAllCallback,
            IoFinishCallback,
            ReadMemoryFailureCallback,
            SecondaryFlagsCallback,
            IsProcessSnapshotCallback,
            VmStartCallback,
            VmQueryCallback,
            VmPreReadCallback,
        }

        public struct MINIDUMP_CALLBACK_INFORMATION
        {
            public IntPtr CallbackRoutine;
            public PVOID CallbackParam;
        }

        public struct MINIDUMP_CALLBACK_OUTPUT
        {
            public int Status; // HRESULT
        }

        [Flags]
        public enum PSS_CAPTURE_FLAGS : uint
        {
            PSS_CAPTURE_NONE = 0x00000000,
            PSS_CAPTURE_VA_CLONE = 0x00000001,
            PSS_CAPTURE_RESERVED_00000002 = 0x00000002,
            PSS_CAPTURE_HANDLES = 0x00000004,
            PSS_CAPTURE_HANDLE_NAME_INFORMATION = 0x00000008,
            PSS_CAPTURE_HANDLE_BASIC_INFORMATION = 0x00000010,
            PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION = 0x00000020,
            PSS_CAPTURE_HANDLE_TRACE = 0x00000040,
            PSS_CAPTURE_THREADS = 0x00000080,
            PSS_CAPTURE_THREAD_CONTEXT = 0x00000100,
            PSS_CAPTURE_THREAD_CONTEXT_EXTENDED = 0x00000200,
            PSS_CAPTURE_RESERVED_00000400 = 0x00000400,
            PSS_CAPTURE_VA_SPACE = 0x00000800,
            PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION = 0x00001000,
            PSS_CREATE_BREAKAWAY_OPTIONAL = 0x04000000,
            PSS_CREATE_BREAKAWAY = 0x08000000,
            PSS_CREATE_FORCE_BREAKAWAY = 0x10000000,
            PSS_CREATE_USE_VM_ALLOCATIONS = 0x20000000,
            PSS_CREATE_MEASURE_PERFORMANCE = 0x40000000,
            PSS_CREATE_RELEASE_SECTION = 0x80000000
        }

        public enum PSS_QUERY_INFORMATION_CLASS
        {
            PSS_QUERY_PROCESS_INFORMATION = 0,
            PSS_QUERY_VA_CLONE_INFORMATION = 1,
            PSS_QUERY_AUXILIARY_PAGES_INFORMATION = 2,
            PSS_QUERY_VA_SPACE_INFORMATION = 3,
            PSS_QUERY_HANDLE_INFORMATION = 4,
            PSS_QUERY_THREAD_INFORMATION = 5,
            PSS_QUERY_HANDLE_TRACE_INFORMATION = 6,
            PSS_QUERY_PERFORMANCE_COUNTERS = 7
        }

        [Flags]
        public enum MINIDUMP_TYPE : int
        {
            MiniDumpNormal = 0x00000000,
            MiniDumpWithDataSegs = 0x00000001,
            MiniDumpWithFullMemory = 0x00000002,
            MiniDumpWithHandleData = 0x00000004,
            MiniDumpFilterMemory = 0x00000008,
            MiniDumpScanMemory = 0x00000010,
            MiniDumpWithUnloadedModules = 0x00000020,
            MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
            MiniDumpFilterModulePaths = 0x00000080,
            MiniDumpWithProcessThreadData = 0x00000100,
            MiniDumpWithPrivateReadWriteMemory = 0x00000200,
            MiniDumpWithoutOptionalData = 0x00000400,
            MiniDumpWithFullMemoryInfo = 0x00000800,
            MiniDumpWithThreadInfo = 0x00001000,
            MiniDumpWithCodeSegs = 0x00002000,
            MiniDumpWithoutAuxiliaryState = 0x00004000,
            MiniDumpWithFullAuxiliaryState = 0x00008000,
            MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
            MiniDumpIgnoreInaccessibleMemory = 0x00020000,
            MiniDumpWithTokenInformation = 0x00040000,
            MiniDumpWithModuleHeaders = 0x00080000,
            MiniDumpFilterTriage = 0x00100000,
            MiniDumpValidTypeFlags = 0x001fffff
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate BOOL MiniDumpCallback(PVOID CallbackParam, PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput);
        [DllImport("kernel32")]
        public static extern DWORD PssCaptureSnapshot(HANDLE ProcessHandle, PSS_CAPTURE_FLAGS CaptureFlags, DWORD ThreadContextFlags, out HPSS SnapshotHandle);

        [DllImport("kernel32")]
        public static extern DWORD PssFreeSnapshot(HANDLE ProcessHandle, HPSS SnapshotHandle);

        [DllImport("kernel32")]
        public static extern DWORD PssQuerySnapshot(HPSS SnapshotHandle, PSS_QUERY_INFORMATION_CLASS InformationClass, out IntPtr Buffer, DWORD BufferLength);

        [DllImport("kernel32")]
        public static extern BOOL CloseHandle(HANDLE hObject);

        [DllImport("kernel32")]
        public static extern BOOL GetProcessId(HANDLE hObject);

        [DllImport("dbghelp")]
        public static extern DWORD MiniDumpWriteDump(HANDLE hProcess, DWORD ProcessId, HANDLE hFile, MINIDUMP_TYPE DumpType, PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, PMINIDUMP_CALLBACK_INFORMATION CallbackParam);
        public static BOOL ATPDumpCallbackMethod(PVOID param, PMINIDUMP_CALLBACK_INPUT input, PMINIDUMP_CALLBACK_OUTPUT output)
        {
            unsafe
            {
                if (Marshal.ReadByte(input + sizeof(int) + IntPtr.Size) == 16){
                    var outp = (MINIDUMP_CALLBACK_OUTPUT*)output;
                    outp->Status = 1;
                }
            }
            return 1;
        }
        [Flags]
        public enum CONTEXT_FLAGS : int
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,   //  same as i386
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }


        /// end minidump definitions
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern IntPtr GetProcAddress(
            IntPtr hModule,
            string procName
        );


        [DllImport("advapi32.dll",SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("advapi32.dll")]
        public static extern bool ImpersonateLoggedOnUser(
            IntPtr hToken
         );

        // LookupPrivilegeValue
        [DllImport("advapi32.dll")]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        // OpenProcess
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcessImpersonate(
         ProcessAccessFlags processAccess,
         bool bInheritHandle,
         int processId);
        public static IntPtr OpenProcessImperonateHelper(Process proc, ProcessAccessFlags flags)
        {
            return OpenProcessImpersonate(flags, false, proc.Id);
        }

        // OpenProcessToken
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        // DuplicateToken
        [DllImport("advapi32.dll")]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

        // SetThreadToken
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetThreadToken(IntPtr pHandle, IntPtr hToken);

        // AdjustTokenPrivileges
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
           [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
           ref TOKEN_PRIVILEGES NewState,
           UInt32 BufferLengthInBytes,
           ref TOKEN_PRIVILEGES PreviousState,
           out UInt32 ReturnLengthInBytes);

        // GetCurrentProcess
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();


        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool PrivilegeCheck(
            IntPtr ClientToken,
            ref PRIVILEGE_SET RequiredPrivileges,
            out bool pfResult
            );
        ///
        /// SERVICES DEFINITIONS
        ///
        
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean ChangeServiceConfig(
            IntPtr hService,
            UInt32 nServiceType,
            UInt32 nStartType,
            UInt32 nErrorControl,
            String lpBinaryPathName,
            String lpLoadOrderGroup,
            IntPtr lpdwTagId,
            [In] char[] lpDependencies,
            String lpServiceStartName,
            String lpPassword,
            String lpDisplayName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr OpenService(
            IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(
            string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle")]
        public static extern int CloseServiceHandle(IntPtr hSCObject);

        public const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
        public const uint SERVICE_QUERY_CONFIG = 0x00000001;
        public const uint SERVICE_CHANGE_CONFIG = 0x00000002;
        public const uint SERVICE_ALL_ACCESS =    0x000F01FF;
        public const uint SC_MANAGER_ALL_ACCESS = 0x000F003F;
        public const uint SERVICE_ERROR_IGNORE =  0x00000000;
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean QueryServiceConfig(IntPtr hService, IntPtr intPtrQueryConfig, UInt32 cbBufSize, out UInt32 pcbBytesNeeded);

        [Flags]
        public enum SERVICE_CONTROL : uint
        {
            STOP = 0x00000001,
            PAUSE = 0x00000002,
            CONTINUE = 0x00000003,
            INTERROGATE = 0x00000004,
            SHUTDOWN = 0x00000005,
            PARAMCHANGE = 0x00000006,
            NETBINDADD = 0x00000007,
            NETBINDREMOVE = 0x00000008,
            NETBINDENABLE = 0x00000009,
            NETBINDDISABLE = 0x0000000A,
            DEVICEEVENT = 0x0000000B,
            HARDWAREPROFILECHANGE = 0x0000000C,
            POWEREVENT = 0x0000000D,
            SESSIONCHANGE = 0x0000000E
        }
        internal enum SERVICE_STATE : int
        {
            SERVICE_STOPPED = 0x00000001,
            SERVICE_START_PENDING = 0x00000002,
            SERVICE_STOP_PENDING = 0x00000003,
            SERVICE_RUNNING = 0x00000004,
            SERVICE_CONTINUE_PENDING = 0x00000005,
            SERVICE_PAUSE_PENDING = 0x00000006,
            SERVICE_PAUSED = 0x00000007,
        }

        [Flags]
        internal enum SERVICE_TYPE : int
        {
            SERVICE_KERNEL_DRIVER = 0x00000001,
            SERVICE_FILE_SYSTEM_DRIVER = 0x00000002,
            SERVICE_WIN32_OWN_PROCESS = 0x00000010,
            SERVICE_WIN32_SHARE_PROCESS = 0x00000020,
            SERVICE_INTERACTIVE_PROCESS = 0x00000100
        }
        public struct SERVICE_STATUS
        {
            public SERVICE_TYPE dwServiceType;
            public SERVICE_STATE dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ControlService(IntPtr hService, SERVICE_CONTROL dwControl, ref SERVICE_STATUS lpServiceStatus);

        public struct QueryServiceConfigStruct
        {
            public int serviceType;
            public int startType;
            public int errorControl;
            public IntPtr binaryPathName;
            public IntPtr loadOrderGroup;
            public int tagID;
            public IntPtr dependencies;
            public IntPtr startName;
            public IntPtr displayName;
        }
        ///

        // LSA DUMP DEFINITIONS
        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        public enum LSA_AccessPolicy : long
        {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
            POLICY_TRUST_ADMIN = 0x00000008L,
            POLICY_CREATE_ACCOUNT = 0x00000010L,
            POLICY_CREATE_SECRET = 0x00000020L,
            POLICY_CREATE_PRIVILEGE = 0x00000040L,
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
            POLICY_SERVER_ADMIN = 0x00000400L,
            POLICY_LOOKUP_NAMES = 0x00000800L,
            POLICY_NOTIFICATION = 0x00001000L
        }

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaRetrievePrivateData(
          IntPtr PolicyHandle,
          ref LSA_UNICODE_STRING KeyName,
          out IntPtr PrivateData
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaStorePrivateData(
          IntPtr policyHandle,
          ref LSA_UNICODE_STRING KeyName,
          ref LSA_UNICODE_STRING PrivateData
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaOpenPolicy(
          ref LSA_UNICODE_STRING SystemName,
          ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
          uint DesiredAccess,
          out IntPtr PolicyHandle
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaNtStatusToWinError(
          uint status
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaClose(
          IntPtr policyHandle
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaFreeMemory(
          IntPtr buffer
        );
        /// token stuff below

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_STATISTICS
        {
            public LUID TokenId;
            public LUID AuthenticationId;
            public uint ExpirationTime;
            public uint TokenType;
            public uint ImpersonationLevel;
            public uint DynamicCharged;
            public uint DynamicAvailable;
            public uint GroupCount;
            public uint PrivilegeCount;
            public LUID ModifiedId;
        }
        [DllImport("Secur32.dll", SetLastError = false)]

        public static extern uint LsaGetLogonSessionData(IntPtr luid, out IntPtr ppLogonSessionData);
        [StructLayout(LayoutKind.Sequential)]

        public struct SECURITY_LOGON_SESSION_DATA

        {

            public UInt32 Size;
            public LUID LoginID;
            public LSA_UNICODE_STRING Username;
            public LSA_UNICODE_STRING LoginDomain;
            public LSA_UNICODE_STRING AuthenticationPackage;
            public UInt32 LogonType;
            public UInt32 Session;
            public IntPtr PSiD;
            public UInt64 LoginTime;
            public LSA_UNICODE_STRING LogonServer;
            public LSA_UNICODE_STRING DnsDomainName;
            public LSA_UNICODE_STRING Upn;

        }
        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

        public enum LogonFlags
        {
            /// <summary>
            /// Log on, then load the user's profile in the HKEY_USERS registry key. The function
            /// returns after the profile has been loaded. Loading the profile can be time-consuming,
            /// so it is best to use this value only if you must access the information in the
            /// HKEY_CURRENT_USER registry key.
            /// NOTE: Windows Server 2003: The profile is unloaded after the new process has been
            /// terminated, regardless of whether it has created child processes.
            /// </summary>
            /// <remarks>See LOGON_WITH_PROFILE</remarks>
            WithProfile = 1,
            /// <summary>
            /// Log on, but use the specified credentials on the network only. The new process uses the
            /// same token as the caller, but the system creates a new logon session within LSA, and
            /// the process uses the specified credentials as the default credentials.
            /// This value can be used to create a process that uses a different set of credentials
            /// locally than it does remotely. This is useful in inter-domain scenarios where there is
            /// no trust relationship.
            /// The system does not validate the specified credentials. Therefore, the process can start,
            /// but it may not have access to network resources.
            /// </summary>
            /// <remarks>See LOGON_NETCREDENTIALS_ONLY</remarks>
            NetCredentialsOnly
        }
        public enum CreationFlags

        {

            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000

        }
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            IntPtr lpTokenAttributes,
            uint ImpersonationLevel,
            uint TokenType,
            out IntPtr phNewToken);
        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, LogonFlags dwLogonFlags, string lpApplicationName, string lpCommandLine, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);


        /// file mapping stuff
         [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr CreateFileA(
         [MarshalAs(UnmanagedType.LPStr)] string filename,
         [MarshalAs(UnmanagedType.U4)] FileAccess access,
         [MarshalAs(UnmanagedType.U4)] FileShare share,
         IntPtr securityAttributes,
         [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
         [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
         IntPtr templateFile);

        [Flags]
        public enum FileMapProtection : uint
        {
            PageReadonly = 0x02,
            PageReadWrite = 0x04,
            PageWriteCopy = 0x08,
            PageExecuteRead = 0x20,
            PageExecuteReadWrite = 0x40,
            SectionCommit = 0x8000000,
            SectionImage = 0x1000000,
            SectionNoCache = 0x10000000,
            SectionReserve = 0x4000000,
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFileMapping(
            IntPtr hFile,
            IntPtr lpFileMappingAttributes,
            FileMapProtection flProtect,
            uint dwMaximumSizeHigh,
            uint dwMaximumSizeLow,
            [MarshalAs(UnmanagedType.LPStr)] string lpName);
        public enum FileMapAccessType : uint
        {
            Copy = 0x01,
            Write = 0x02,
            Read = 0x04,
            AllAccess = 0x08,
            Execute = 0x20,
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr MapViewOfFileEx(IntPtr hFileMappingObject,
           FileMapAccessType dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow,
           UIntPtr dwNumberOfBytesToMap, IntPtr lpBaseAddress);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);
    }

}
