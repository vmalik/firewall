using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using firewall.Utils;
using System.Diagnostics;

namespace firewalltest.UtilsTest
{
    class IPmatchTest
    {
        static public bool run()
        {
            UInt16[] ip1 = IPParser.ParseIPAddress("1.2.3.4");
            UInt16[] ip2 = IPParser.ParseIPAddress("1.2.3.4");
            UInt16 mask = 32;
            Debug.Assert(IPMatch.IsIPMatching(ip1, mask, ip2));

            ip2 = IPParser.ParseIPAddress("1.2.3.5");
            mask = 32;
            Debug.Assert(!IPMatch.IsIPMatching(ip1, mask, ip2));

            ip2 = IPParser.ParseIPAddress("1.2.3.5");
            mask = 24;
            Debug.Assert(IPMatch.IsIPMatching(ip1, mask, ip2));

            ip2 = IPParser.ParseIPAddress("166.66.66.54");
            mask = 0;
            Debug.Assert(IPMatch.IsIPMatching(ip1, mask, ip2));
            
            return true;
        }
    }
}
