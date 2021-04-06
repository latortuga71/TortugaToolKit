using System;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;


namespace TurtleToolKitAD
{
    class ActiveDirectory
    {
        public static void ListDomainsInForest()
        {
            PrincipalContext principalCxt = new PrincipalContext(ContextType.Domain);
            Forest f = Forest.GetCurrentForest();
            DomainCollection myDomains = f.Domains;
            foreach (Domain obj in myDomains)
            {
                Console.WriteLine("::: {0} :::", obj.Name);
            }
        }
        public static void ListComputers()
        {
            PrincipalContext principalCxt = new PrincipalContext(ContextType.Domain);
            ComputerPrincipal pc = new ComputerPrincipal(principalCxt);
            pc.Name = "*";
            PrincipalSearcher searcher = new PrincipalSearcher();
            searcher.QueryFilter = pc;
            PrincipalSearchResult<Principal> results = searcher.FindAll();
            foreach (Principal c in results)
            {
                Console.WriteLine("::: {0} :::", c.Name);
            }

        }
        public static void ListGroups()
        {
            PrincipalContext principalCxt = new PrincipalContext(ContextType.Domain);
            GroupPrincipal grp = new GroupPrincipal(principalCxt);
            grp.Name = "*";
            PrincipalSearcher searcher = new PrincipalSearcher();
            searcher.QueryFilter = grp;
            PrincipalSearchResult<Principal> results = searcher.FindAll();
            foreach (Principal g in results)
            {
                Console.WriteLine("::: {0} :::", g.Name);
            }
        }
        public static void ListUsers()
        {
            PrincipalContext principalCxt = new PrincipalContext(ContextType.Domain);
            UserPrincipal usr = new UserPrincipal(principalCxt);
            PrincipalSearcher searcher = new PrincipalSearcher();
            usr.Name = "*";
            searcher.QueryFilter = usr;
            PrincipalSearchResult<Principal> results = searcher.FindAll();
            foreach (Principal u in results)
            {
                Console.WriteLine("::: {0} :::",u.Name);
            }

        }
        public static void ListUserGroupMemberships(string userName)
        {
            PrincipalContext principalCxt = new PrincipalContext(ContextType.Domain);
            UserPrincipal usr = new UserPrincipal(principalCxt);
            usr.Name = userName;
            PrincipalSearcher searcher = new PrincipalSearcher();
            searcher.QueryFilter = usr;
            PrincipalSearchResult<Principal> results = searcher.FindAll();
            foreach (Principal u in results)
            {
                foreach (Principal ug in u.GetGroups())
                {
                    Console.WriteLine("::: {0} Member of -> {1} :::", u.Name, ug.Name);
                }
            }
        }
    }
}
