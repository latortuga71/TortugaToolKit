using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Diagnostics;
using System.Threading;
using System.Net.NetworkInformation;


namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "PingSweep")] // <- seeting cmdlet name and verbs
    [Alias("INVPING")] //<- cmdlet alias
    public class InvokePingSweep : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("s")] public string subnet { get; set; }

        static CountdownEvent countdown;
        static int upCount;
        public static object lockObj = new object();
        const bool resolveNames = true;
        private static List<string> upHosts;

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            upHosts = new List<string>();
            WriteWarning("Only for /24 subnet");
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            upCount = 0;
            ExecutePingSweep(subnet);
            WriteObject(upHosts);
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }
        public static void ExecutePingSweep(string net)
        {
            countdown = new CountdownEvent(1);
            Stopwatch sw = new Stopwatch();
            sw.Start();
            var ipSplit = net.Split('.');
            Array.Resize(ref ipSplit, ipSplit.Length - 1);
            string ipBase = String.Join(".", ipSplit) + ".";
            //string ipBase = "10.0.0.";
            for (int i = 1; i < 255; i++)
            {
                string ip = ipBase + i.ToString();

                Ping p = new Ping();
                p.PingCompleted += new PingCompletedEventHandler(p_PingCompleted);
                countdown.AddCount();
                p.SendAsync(ip, 100, ip);
            }
            countdown.Signal();
            countdown.Wait();
            sw.Stop();
            TimeSpan span = new TimeSpan(sw.ElapsedTicks);
            Console.WriteLine("Took {0} milliseconds. {1} hosts active.", sw.ElapsedMilliseconds, upCount);
        }

        static void p_PingCompleted(object sender, PingCompletedEventArgs e)
        {
            string ip = (string)e.UserState;
            if (e.Reply != null && e.Reply.Status == IPStatus.Success)
            {
                //Console.WriteLine("{0} is up: ({1} ms)", ip, e.Reply.RoundtripTime);
                lock (lockObj)
                {
                    upHosts.Add(ip);
                    upCount++;
                }
            }
            else if (e.Reply == null)
            {
                Console.WriteLine("Pinging {0} failed. (Null Reply object?)", ip);
            }
            countdown.Signal();
        }


    }
}
