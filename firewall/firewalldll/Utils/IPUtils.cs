using System;

namespace firewall.RuleEng
{
    public class IPUtils
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

        public static uint ApplyMask(UInt16 mask, UInt16[] IPAddress)
        {
            if (mask == 0)
            {
                return 0;
            }
            uint maskbitset = uint.MaxValue << (32 - mask);
            return (uint)(((IPAddress[0] << 24) + (IPAddress[1] << 16) + (IPAddress[2] << 8) + IPAddress[3]) & maskbitset);
        }
    }
}
