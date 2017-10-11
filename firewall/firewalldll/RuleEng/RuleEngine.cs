using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Collections;
using firewall.Utils;

namespace firewall.Utils
{
    public class RuleEngine
    {
        private string myRuleFilePath;
        private List<Rule> myRules = null;
        
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
            myRules = new List<Rule>();
            foreach (string line in File.ReadLines(myRuleFilePath))
            {
                Rule rule = null;
                if(RuleParser.TryParse(line, out rule))
                {
                    myRules.Add(rule);
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

        public bool IsAllowed(Packet packet)
        {
            bool isAllowed = false;
            foreach (Rule rule in myRules)
            {
                if(TryRule(rule, packet, out isAllowed))
                {
                    return isAllowed;
                }
            }
            //No rule matched
            return true;
        }

        private bool TryRule(Rule rule, Packet packet, out bool isAllowed)
        {
            isAllowed = false;
            if (!string.Equals(rule.UserName, "*") && !string.Equals(rule.UserName, packet.UserName))
            {
                return false;
            }
            if (!IPMatch.IsIPMatching(rule.IPAddress, rule.Mask, packet.IPAddress))
            {
                return false;
            }
            isAllowed = rule.IsAllowed;
            return true;
        }
    }
}
