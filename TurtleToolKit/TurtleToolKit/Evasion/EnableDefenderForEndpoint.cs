using System;
using NetFwTypeLib;
using System.Management.Automation;
using TurtleToolKitImpersonate;
using TurtleToolKitServices;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Enable, "DefenderForEndpoint")] // <- seeting cmdlet name and verbs
    [Alias("EDFE")] //<- cmdlet alias
    public class EnableDefenderForEndpoint : Cmdlet
    {
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // Process each item in pipeline
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            WriteWarning("Need to elevate to SYSTEM for this");
            ExecuteEnableDefenderForEndpoint();
            return;
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }


        public bool ExecuteEnableDefenderForEndpoint()
        {
            try
            {
                Impersonator.ElevateToSystem();
                Services.StartTrustedInstaller();
                Impersonator.ElevateToTs();
                ExecuteDeleteFirewallBlock(); // delete firewall rules
                Services.StartWinDefend(); //start windefend
                ExecuteDeleteFirewallBlock(); // delete firewall rules
                WriteVerbose("successfully enabled defender");
                Impersonator.RevokePrivs();
                return true;
            }
            catch
            {
                WriteWarning("Failed to revert defender for endpoint");
                Impersonator.RevokePrivs();
                return false;
            }
        }

        // functions to be called by cmdlet\
        
        static void ExecuteDeleteFirewallBlock()
        {
            DeleteBlockRule("windefend", "windefendBlocker", "windefend");
            DeleteBlockRule("senseCncProxy", "senseCncProxyBlocker", "", "%ProgramFiles%\\Windows Defender Advanced Threat Protection\\SenseCncProxy.exe");
            DeleteBlockRule("sense", "senseblocker", "sense");
        }
        
        static bool DeleteBlockRule(string description, string ruleName, string serviceName = "", string fullPath = "")
        {
            if (fullPath == "")
            {
                // rule by service name
                INetFwRule firewallRule = (INetFwRule)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWPolicy2"));
                firewallRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                firewallRule.Description = description;
                firewallRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
                firewallRule.Enabled = true;
                firewallRule.serviceName = serviceName;
                firewallRule.InterfaceTypes = "All";
                firewallRule.Name = ruleName;
                //firewallRule.ApplicationName = fullPath;
                firewallPolicy.Rules.Remove(ruleName);
                return true;
            }
            else
            {
                // rule by fullpath
                INetFwRule firewallRule = (INetFwRule)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWPolicy2"));
                firewallRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                firewallRule.Description = description;
                firewallRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
                firewallRule.Enabled = true;
                //firewallRule.serviceName = serviceName;
                firewallRule.InterfaceTypes = "All";
                firewallRule.Name = ruleName;
                firewallRule.ApplicationName = fullPath;
                firewallPolicy.Rules.Remove(ruleName);
                return true;
            }
        }
    }
}