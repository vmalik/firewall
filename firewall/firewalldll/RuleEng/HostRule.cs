using System;

namespace firewall.RuleEng
{
    public class HostRule : BaseRule
    {
        private string myHostname;

        private static readonly uint RULE_FIELDS_COUNT = 3;

        public HostRule(string username, string hostname, bool isAllowed) : base(username, isAllowed)
        {
            if (String.IsNullOrEmpty(hostname))
            {
                throw new ArgumentException("hostname should have four octets");
            }
            myHostname = hostname;
        }

        
        public string HostName
        {
            get
            {
                return myHostname;
            }
        }
        public static bool CreateHostnameRule(string line, out HostRule rule)
        {
            rule = null;
            //System.Console.WriteLine(line);
            string[] fields = line.Split('|');
            if (fields.Length != RULE_FIELDS_COUNT)
            {
                return false;
            }

            bool isAllowed = false;
            if (!BaseRule.TryParseIsAllowed(fields[2], out isAllowed))
            {
                return false;
            }

            string username = fields[0];
            string hostname = fields[1];
            rule = new HostRule(username, hostname, isAllowed);
            return true;

        }
    }
}
