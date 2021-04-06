using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using TurtleToolKitSQL;

namespace TurtleToolKit
{
    [Cmdlet(VerbsCommon.Search, "SQLDbs")] // <- seeting cmdlet name and verbs
    [Alias("SSQLDB")] //<- cmdlet alias
    public class SearchSqlDbs : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("h")] public static string targetServer { get; set; }
        [Parameter(Mandatory = true)] [Alias("d")] public static string database { get; set; }
        [Parameter(Mandatory = true)] [Alias("ad")] public static bool useAdCreds { get; set; }
        [Parameter(Mandatory = false)] [Alias("u")] public static string user { get; set; }
        [Parameter(Mandatory = false)] [Alias("p")] public static string password { get; set; }


        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }
        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            SQL sql = GetSQLInstance();
            sql.ConnectToDb();
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }




        /// returns sql instance using cmdlet parameters
        public static SQL GetSQLInstance()
        {
            SQL sql;
            /// create connection
            if (useAdCreds)
            {
                sql = new SQL(targetServer, database, useAdCreds,user,password);
                return sql;
            }
            sql = new SQL(targetServer, database, useAdCreds);
            return sql;

        }
    }
}
