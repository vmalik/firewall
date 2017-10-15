using System;


namespace firewall.RuleEng
{
    public class IPRule : BaseRule
    {
        private UInt16[] myIPAddress = new UInt16[4];
        private UInt16 myMask = 0;
        private uint myMaskedIPAddress = 0;

        private static readonly UInt16 NOMASK = 32;
        private static readonly uint RULE_FIELDS_COUNT = 3;

        public IPRule(string username, UInt16[] ipAddress, UInt16 mask, bool isAllowed) : base(username, isAllowed)
        {
            if (ipAddress.Length != 4)
            {
                throw new ArgumentException("ipAddress should have four octets");
            }
            myIPAddress = ipAddress;
            myMask = mask;
            myMaskedIPAddress = IPUtils.ApplyMask(myMask, myIPAddress);
        }
        public UInt16[] IPAddress
        {
            get
            {
                return myIPAddress;
            }
        }

        public uint MaskedIPAddress
        {
            get
            {
                return myMaskedIPAddress;
            }
        }

        public UInt16 Mask
        {
            get
            {
                return myMask;
            }
        }


        public static bool CreateIPRule(string line, out IPRule rule)
        {
            rule = null;
            //System.Console.WriteLine(line);
            string[] fields = line.Split('|');
            if (fields.Length != RULE_FIELDS_COUNT)
            {
                return false;
            }

            string[] ipAddressWithMask = fields[1].Split('/');
            if (ipAddressWithMask.Length != 1 && ipAddressWithMask.Length != 2)
            {
                return false;
            }

            UInt16[] ipAddress = IPUtils.ParseIPAddress(ipAddressWithMask[0]);
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
            if (!BaseRule.TryParseIsAllowed(fields[2], out isAllowed))
            {
                return false;
            }

            string username = fields[0];
            rule = new IPRule(username, ipAddress, mask, isAllowed);
            return true;
        }
    }
}
