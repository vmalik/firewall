using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using firewall.Utils;
using System.Diagnostics;

namespace firewalltest.UtilsTest
{
    class ipparserTest
    {
        static public bool run()
        {
            Debug.Assert(IPParser.ParseIPAddress("dfdf")==null);
            Debug.Assert(IPParser.ParseIPAddress("256.2.3.4") == null);
            Debug.Assert(IPParser.ParseIPAddress("2.3.4") == null);

            UInt16[] ip = IPParser.ParseIPAddress("1.2.3.4");
            Debug.Assert(ip[0] == 1);
            Debug.Assert(ip[1] == 2);
            Debug.Assert(ip[2] == 3);
            Debug.Assert(ip[3] == 4);
            return true;
        }
    }
}
