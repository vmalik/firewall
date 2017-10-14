using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;


namespace firewall.RuleEng
{
    public class RuleEngine
    {
        private string myRuleFilePath;
        private Dictionary<uint, Rule> myRules = null;
        private Dictionary<string, HashSet<uint>> myUserToRuleMap = new Dictionary<string, HashSet<uint>>();
            
        // Dictionary of mask of Dictionary of masked IPs e.g. <24, <0x01000000, [2,5,6]>>
        private Dictionary<UInt16, Dictionary <uint,  HashSet<uint>>> myMaskedIPToRuleMap = new Dictionary<UInt16, Dictionary<uint, HashSet<uint>>>();

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
            myRules = new Dictionary<uint, Rule>();

            uint ruleId = 0;
            foreach (string line in File.ReadLines(myRuleFilePath))
            {
                Rule rule = null;
                if (RuleParser.TryParse(line, out rule))
                {
                    myRules.Add(ruleId, rule);
                    BuilUserToRuleMap(ruleId, rule);
                    BuildMaskedIPtoRuleMap(ruleId, rule);

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

        private void BuildMaskedIPtoRuleMap(uint ruleId, Rule rule)
        {
            if (!myMaskedIPToRuleMap.ContainsKey(rule.Mask))
            {
                myMaskedIPToRuleMap.Add(rule.Mask, new Dictionary<uint, HashSet<uint>>());
            }

            Dictionary<uint, HashSet<uint>> ipRuleMap = null;

            if (myMaskedIPToRuleMap.TryGetValue(rule.Mask, out ipRuleMap))
            {
                if (ipRuleMap.ContainsKey(rule.MaskedIPAddress))
                {
                    HashSet<uint> ruleSet = null;
                    ipRuleMap.TryGetValue(rule.MaskedIPAddress, out ruleSet);
                    ruleSet.Add(ruleId);
                }
                else
                {
                    HashSet<uint> ruleSet = new HashSet<uint>();
                    ruleSet.Add(ruleId);
                    ipRuleMap.Add(rule.MaskedIPAddress, ruleSet);
                }
            }
        }

        private void BuilUserToRuleMap(uint ruleId, Rule rule)
        {
            if (myUserToRuleMap.ContainsKey(rule.UserName))
            {
                HashSet<uint> ruleSet = null;
                myUserToRuleMap.TryGetValue(rule.UserName, out ruleSet);
                ruleSet.Add(ruleId);
            }
            else
            {
                HashSet<uint> ruleSet = new HashSet<uint>();
                ruleSet.Add(ruleId);
                myUserToRuleMap.Add(rule.UserName, ruleSet);
            }
        }

        public bool IsAllowed(Packet packet)
        {
            //Console.WriteLine("Processing " + packet.UserName + "in thread : " + Thread.CurrentThread.ManagedThreadId);
            //Rules for matching name
            HashSet<uint> userRuleSet = FindRulesMatchingUserName(packet);
            if (userRuleSet.Count == 0)
            {
                return true;
            }
            //Console.WriteLine("FindRulesMatchingUserName count " + userRuleSet.Count);
            
            //Rules for same masked ip
            HashSet<uint> maskedIPRuleSet = FindRulesMatchingIP(packet);
            if (maskedIPRuleSet == null || maskedIPRuleSet.Count == 0)
            {
                return true;
            }
            //Console.WriteLine("FindRulesMatchingIP count " + maskedIPRuleSet.Count);

            userRuleSet.IntersectWith(maskedIPRuleSet);

            //Console.WriteLine("IntersectWith FindRulesMatchingUserName FindRulesMatchingIP count " + userRuleSet.Count);
            if (userRuleSet.Count == 0)
            {
                //No rule matched
                return true;
            }

            uint ruleID = userRuleSet.Min(); //Only need to use the first mathcing rule
            Rule firstMatchedRule = null;
            myRules.TryGetValue(ruleID, out firstMatchedRule);
            return firstMatchedRule.IsAllowed;
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
