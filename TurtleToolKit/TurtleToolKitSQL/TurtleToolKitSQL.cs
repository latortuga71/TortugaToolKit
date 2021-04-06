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
        public SQL(string srv, string db,bool ADCreds=false,string user="",string password="")
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
            if (useADCreds)
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
            Console.WriteLine("::: Current DB {0} setting variable :::", commandReader[0]);
            startingDb = commandReader[0].ToString();
            commandReader.Close();
        }


    }
}
