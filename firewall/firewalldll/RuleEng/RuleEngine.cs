using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using firewall.Utils;


namespace firewall.RuleEng
{
    public class RuleEngine
    {
        private string myRuleFilePath;
        private Dictionary<uint, IRule> myRules = null;
        private Dictionary<string, HashSet<uint>> myUserToRuleMap = new Dictionary<string, HashSet<uint>>();
            
        // Dictionary of mask of Dictionary of masked IPs e.g. <24, <0x01000000, [2,5,6]>>
        private Dictionary<UInt16, Dictionary <uint,  HashSet<uint>>> myMaskedIPToRuleMap = new Dictionary<UInt16, Dictionary<uint, HashSet<uint>>>();

        private HashSet<uint> myHostnameRuleSet = new HashSet<uint>();

        public RuleEngine(string ruleFilePath)
        {
            if (String.IsNullOrEmpty(ruleFilePath))
            {
                throw new ArgumentException("ruleFilePath can't be null or empty");
            }
            myRuleFilePath = ruleFilePath;
            Initialize();
        }

        private void Initialize()
        {
            myRules = new Dictionary<uint, IRule>();

            uint ruleId = 0;
            foreach (string line in File.ReadLines(myRuleFilePath))
            {
                IRule rule = RuleFactory.CreateRule(line);
                if (rule != null)
                {
                    myRules.Add(ruleId, rule);
                    BuilUserToRuleMap(ruleId, rule);
                    BuildMaskedIPtoRuleMap(ruleId, rule);
                    BuildHostnameRuleSet(ruleId, rule);

                    ruleId++;
                }
            }
            
            /*
            Console.WriteLine("***RULES***");
            foreach (Rule rule in myRules)
            {
                Console.WriteLine(rule.ToString());
            }
            Console.WriteLine("***RULES END***");
            */
        }

        private void BuildHostnameRuleSet(uint ruleId, IRule rule)
        {
            HostRule hostRule = rule as HostRule;
            if (hostRule != null)
            {
                myHostnameRuleSet.Add(ruleId);
            }
        }

        private void BuildMaskedIPtoRuleMap(uint ruleId, IRule rule)
        {
            IPRule ipRule = rule as IPRule;
            if (ipRule != null)
            {
                if (!myMaskedIPToRuleMap.ContainsKey(ipRule.Mask))
                {
                    myMaskedIPToRuleMap.Add(ipRule.Mask, new Dictionary<uint, HashSet<uint>>());
                }

                Dictionary<uint, HashSet<uint>> ipRuleMap = null;

                if (myMaskedIPToRuleMap.TryGetValue(ipRule.Mask, out ipRuleMap))
                {
                    if (ipRuleMap.ContainsKey(ipRule.MaskedIPAddress))
                    {
                        HashSet<uint> ruleSet = null;
                        ipRuleMap.TryGetValue(ipRule.MaskedIPAddress, out ruleSet);
                        ruleSet.Add(ruleId);
                    }
                    else
                    {
                        HashSet<uint> ruleSet = new HashSet<uint>();
                        ruleSet.Add(ruleId);
                        ipRuleMap.Add(ipRule.MaskedIPAddress, ruleSet);
                    }
                }
            }
        }

        private void BuilUserToRuleMap(uint ruleId, IRule rule)
        {
            BaseRule baserule = rule as BaseRule;
            if (baserule != null)
            {
                if (myUserToRuleMap.ContainsKey(baserule.UserName))
                {
                    HashSet<uint> ruleSet = null;
                    myUserToRuleMap.TryGetValue(baserule.UserName, out ruleSet);
                    ruleSet.Add(ruleId);
                }
                else
                {
                    HashSet<uint> ruleSet = new HashSet<uint>();
                    ruleSet.Add(ruleId);
                    myUserToRuleMap.Add(baserule.UserName, ruleSet);
                }
            }
        }

        public bool IsAllowed(Packet packet)
        {
            uint ruleId;
            if (!FindFirstMatchingRule(packet, out ruleId))
            {
                return true;
            }

            IRule firstMatchedRule = null;
            myRules.TryGetValue(ruleId, out firstMatchedRule);
            return firstMatchedRule.IsAllowed();
        }

        private bool FindFirstMatchingRule(Packet packet, out uint ruleId)
        {
            SortedSet<uint> matchingRuleSet = new SortedSet<uint>();
            ruleId = uint.MaxValue;
            //Console.WriteLine("Processing " + packet.UserName + "in thread : " + Thread.CurrentThread.ManagedThreadId);
            //Rules for matching name
            matchingRuleSet.UnionWith(FindRulesMatchingUserName(packet));
            if (matchingRuleSet.Count == 0)
            {
                return false;
            }
            //Console.WriteLine("FindRulesMatchingUserName count " + userRuleSet.Count);

            //Rules for same masked ip
            HashSet<uint> maskedIPAllHostRuleSet = FindRulesMatchingIP(packet);
            //Console.WriteLine("FindRulesMatchingIP count " + maskedIPRuleSet.Count);

            //Add all Rules with hostname
            maskedIPAllHostRuleSet.UnionWith(myHostnameRuleSet);
            //Console.WriteLine("FindRulesMatchingIP count " + maskedIPRuleSet.Count);

            matchingRuleSet.IntersectWith(maskedIPAllHostRuleSet);
            //Console.WriteLine("IntersectWith FindRulesMatchingUserName FindRulesMatchingIP count " + userRuleSet.Count);
            if (matchingRuleSet.Count == 0)
            {
                //No rule matched
                return false;
            }

            // ruleId = matchingRuleSet.Min();
            bool matched = false;
            foreach (uint id in matchingRuleSet)
            {
                if (!myHostnameRuleSet.Contains(id))
                {
                    matched = true;
                    ruleId = id;
                    break;
                }
                IRule rule;
                Debug.Assert(myRules.TryGetValue(id, out rule));

                HostRule hostRule = rule as HostRule;
                Debug.Assert(hostRule != null);

                string packetHost =  DNSlookupHelper.lookupCachedHost(packet.IPAddress);
                if (string.Equals(packetHost, hostRule.HostName))
                {
                    matched = true;
                    ruleId = id;
                    break;
                }
            }
            return matched;
        }
        private HashSet<uint> FindRulesMatchingIP(Packet packet)
        {
            HashSet<uint> maskedIPRuleSet = new HashSet<uint>();
            foreach (UInt16 mask in myMaskedIPToRuleMap.Keys)
            {
                uint maskedPacketIP = IPUtils.ApplyMask(mask, packet.IPAddress);
                Dictionary<uint, HashSet<uint>> ipRuleMap = null;
                if (myMaskedIPToRuleMap.TryGetValue(mask, out ipRuleMap))
                {
                    HashSet<uint> ruleSet = null;
                    ipRuleMap.TryGetValue(maskedPacketIP, out ruleSet);
                    if (ruleSet != null && ruleSet.Count != 0)
                    {
                        maskedIPRuleSet.UnionWith(ruleSet);
                    }
                }
            }
            return maskedIPRuleSet;
        }

        private HashSet<uint> FindRulesMatchingUserName(Packet packet)
        {
            HashSet<uint> userRuleSet = new HashSet<uint>();
            HashSet<uint> sameUserRuleSet = new HashSet<uint>();
            if (myUserToRuleMap.TryGetValue(packet.UserName, out sameUserRuleSet))
            {
                userRuleSet.UnionWith(sameUserRuleSet);
            }

            //Rules for "*" as name
            HashSet<uint> globalUserRuleSet;
            if (myUserToRuleMap.TryGetValue("*", out globalUserRuleSet))
            {
                userRuleSet.UnionWith(globalUserRuleSet);
            }
            return userRuleSet;
        }
    }
}
