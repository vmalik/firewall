using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace firewall.Utils
{
    public class IPParser
    {
        public static UInt16[] ParseIPAddress(string ipField)
        {
            string[] fields = ipField.Split('.');
            if (fields.Length != 4)
            {
                return null;
            }
            UInt16[] ipAddress = new UInt16[4];
            for (int i = 0; i < 4; i++)
            {
                if (!UInt16.TryParse(fields[i], out ipAddress[i]) || ipAddress[i] > 255)
                {
                    return null;
                }
            }
            return ipAddress;
        }
    }
}
