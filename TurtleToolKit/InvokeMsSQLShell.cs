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
        [Parameter(Mandatory = false)] [Alias("u")] public string user { get; set; }
        [Parameter(Mandatory = false)] [Alias("p")] public string password { get; set; }
        [Parameter(Mandatory = true)] [Alias("q")] public string query { get; set; }

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
            //ExecuteSQLShell(sql);
            sql.CloseDb();
        }
        //ExecuteSearchDB(sql);
        //WriteWarning("Use information listed above to run subsequent cmdlets");
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        public static bool ExecuteSQLShell(SQL sqlObj)
        {
            // connect
            if (!sqlObj.ConnectToDb())
                return false;
            // shell on linked server
            // enable rpc out
            // EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT APPSRV01
            // check if enabled
            // enable xp Cmd shell "EXEC ('sp_configure ''xp_cmdshell'',1; RECONFIGURE;') AT $currentSrv"
            // check if enabled
            // attempt to execute code 
            //EXEC('xp_cmdshell ''whoami''') AT $currentSrv"
            // ask if want interactive shell or just run one command at at time

            //
            //.........
            // shell on non linked server
            return true;

        }
    }
}
