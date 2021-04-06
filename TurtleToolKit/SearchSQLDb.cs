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
        [Parameter(Mandatory = true)] [Alias("h")] public string targetServer { get; set; }
        [Parameter(Mandatory = true)] [Alias("d")] public string database { get; set; }
        [Parameter(Mandatory = true)] [Alias("ad")] public bool useAdCreds { get; set; }
        [Parameter(Mandatory = false)] [Alias("u")] public string user { get; set; }
        [Parameter(Mandatory = false)] [Alias("p")] public string password { get; set; }


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
            if (!useAdCreds)
            {
                sql = new SQL(targetServer, database, useAdCreds, user, password);
            } else
            {
                sql = new SQL(targetServer, database, useAdCreds);
            }
            ExecuteSearchDB(sql);
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }

        public static bool ExecuteSearchDB(SQL sqlObj)
        {
            if (!sqlObj.ConnectToDb())
                return false;
            // start enumeration
            sqlObj.GetCurrentDb();
            sqlObj.GetCurrentDbUser();
            sqlObj.GetCurrentDbUserContext();
            sqlObj.CheckAllRoles();



            // End of func
            sqlObj.CloseDb();
            return true;
            
        }



    }
}
