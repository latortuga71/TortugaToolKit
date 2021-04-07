using System;
using System.Collections.Generic;
using System.Management.Automation;
using TurtleToolKitSQL;

namespace TurtleToolKit
{
    [Cmdlet(VerbsCommon.Get, "SQLInfo")] // <- seeting cmdlet name and verbs
    [Alias("GSQLI")] //<- cmdlet alias
    public class GetSQLInfo : Cmdlet
    {
        [Parameter(Mandatory = true)] [Alias("h")] public string targetServer { get; set; }
        [Parameter(Mandatory = true)] [Alias("d")] public string database { get; set; }
        [Parameter(Mandatory = true)] [Alias("ad")] public bool useAdCreds { get; set; }
        [Parameter(Mandatory = false)] [Alias("u")] public string user { get; set; }
        [Parameter(Mandatory = false)] [Alias("p")] public string password { get; set; }

        public static List<string> linkedServers;
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
            } else
            {
                sql = new SQL(targetServer, database, useAdCreds, user, password);
            }
            ExecuteSearchDB(sql);
            WriteWarning("Use information listed above to run subsequent cmdlets");
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
            sqlObj.GetLoggedInUser();
            sqlObj.GetCurrentDbUser();
            sqlObj.GetCurrentDbUserContext();
            sqlObj.CheckAllRoles();
            sqlObj.GetImpersonatableUsers();
            Console.WriteLine("::: Attempting to check if can impersonate users ::: ");
            foreach (string u in sqlObj.LoginsCanBeImpersonated)
            {
                sqlObj.ImpersonateDbLogin(u);
                sqlObj.GetCurrentDbUser();
                sqlObj.CheckAllRoles();
                sqlObj.RevertUser();
            }
            sqlObj.CheckXpShellEnabled();
            sqlObj.GetLinkedServers();
            sqlObj.LinkedServerEnumeration();
            // End of func
            sqlObj.CloseDb();
            return true;
            
        }



    }
}
