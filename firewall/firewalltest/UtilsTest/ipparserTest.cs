using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using firewall.RuleEng;
using System.Diagnostics;

namespace firewalltest.UtilsTest
{
    class ipparserTest
    {
        static public bool run()
        {
            Debug.Assert(IPUtils.ParseIPAddress("dfdf")==null);
            Debug.Assert(IPUtils.ParseIPAddress("256.2.3.4") == null);
            Debug.Assert(IPUtils.ParseIPAddress("2.3.4") == null);

            UInt16[] ip = IPUtils.ParseIPAddress("1.2.3.4");
            Debug.Assert(ip[0] == 1);
            Debug.Assert(ip[1] == 2);
            Debug.Assert(ip[2] == 3);
            Debug.Assert(ip[3] == 4);
            return true;
        }
    }
}
