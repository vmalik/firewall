using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace firewall.Utils
{
    public class IPMatch
    {
        public static bool IsIPMatching(UInt16[] iPAddress1, UInt16 mask, UInt16[] iPAddress2)
        {
            if (mask == 0)
            {
                return true;
            }
            uint maskbitset = uint.MaxValue << (32 - mask);
            uint maskedIP1 = (uint)(((iPAddress1[0] << 24) + (iPAddress1[1] << 16) + (iPAddress1[2] << 8) + iPAddress1[3]) & maskbitset);
            uint maskedIP2 = (uint)(((iPAddress2[0] << 24) + (iPAddress2[1] << 16) + (iPAddress2[2] << 8) + iPAddress2[3]) & maskbitset);

            if (maskedIP1 == maskedIP2)
            {
                return true;
            }
            return false;
        }
    }
}
