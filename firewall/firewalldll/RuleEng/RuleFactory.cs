﻿
namespace firewall.RuleEng
{
    class RuleFactory
    {
        public static IRule CreateRule(string line)
        {
            IPRule ipRule = null;
            if (IPRule.CreateIPRule(line, out ipRule))
            {
                return ipRule;
            }
            
            HostRule hostRule = null;
            if (HostRule.CreateHostnameRule(line, out hostRule))
            {
                return hostRule;
            }

            return null;
        }
    }
}
