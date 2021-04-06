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
    [Cmdlet(VerbsCommon.Get, "MsSQLQuery")] // <- seeting cmdlet name and verbs
    [Alias("GSQLQ")] //<- cmdlet alias
    public class GetMsSQLQuery : Cmdlet
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
            ExecuteSQLQuery(sql, query);
            sql.CloseDb();
        }
            //ExecuteSearchDB(sql);
            //WriteWarning("Use information listed above to run subsequent cmdlets");
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        public static bool ExecuteSQLQuery(SQL sqlObj,string q)
        {
            // connect
            if (!sqlObj.ConnectToDb())
                return false;
            // run query
            if (!sqlObj.PerformQuery(q))
            {
                return false;
            }
            return true;
        }

    }
}
