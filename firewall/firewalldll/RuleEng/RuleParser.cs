using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace firewall.Utils
{
    public class RuleParser
    {
        private const string ALLOW = "allow";
        private const string DENY = "deny";
        private const UInt16 NOMASK = 32;

        public static bool TryParse(string line, out Rule rule)
        {
            rule = null;
            //System.Console.WriteLine(line);
            string[] fields = line.Split('|');
            if (fields.Length != 3)
            {
                return false;
            }
            string[] ipAddressWithMask = fields[1].Split('/');
            if (ipAddressWithMask.Length != 1 && ipAddressWithMask.Length != 2)
            {
                return false;
            }
            UInt16[] ipAddress = ParseIPAddress(ipAddressWithMask[0]);
            if (ipAddress == null)
            {
                return false;
            }
            UInt16 mask = NOMASK;
            if (ipAddressWithMask.Length == 2 && !UInt16.TryParse(ipAddressWithMask[1], out mask))
            {
                return false;
            }
            bool isAllowed = false;
            if (!TryParseIsAllowed(fields[2], out isAllowed))
            {
                return false;
            }
            string username = fields[0];
            rule = new Rule(username, ipAddress, mask, isAllowed);
            return true;
        }

        private static bool TryParseIsAllowed(string field, out bool isAllowed)
        {
            isAllowed = false;
            if (String.Equals(field, ALLOW, StringComparison.OrdinalIgnoreCase))
            {
                isAllowed = true;
                return true;
            }
            else if (String.Equals(field, DENY, StringComparison.OrdinalIgnoreCase))
            {
                isAllowed = false;
                return true;
            }
            else {
                return false;
            }
        }

        private static UInt16[] ParseIPAddress(string ipField)
        {
            string[] fields = ipField.Split('.');
            if (fields.Length != 4)
            {
                return null;
            }
            UInt16[] ipAddress = new UInt16[4];
            for (int i = 0; i < 4; i++)
            {
                if (!UInt16.TryParse(fields[i], out ipAddress[i]))
                {
                    return null;
                }
            }
            return ipAddress;          
        }
    }
}
