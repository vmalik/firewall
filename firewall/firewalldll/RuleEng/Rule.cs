using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace firewall.Utils
{
    public class Rule
    {
        private string myUsername;
        private UInt16[] myIPAddress = new UInt16[4];
        private UInt16 myMask = 0;
        private bool myIsAllowed = false;

        public Rule(string username, UInt16[] ipAddress, UInt16 mask, bool isAllowed)
        {
            if (String.IsNullOrEmpty(username))
            {
                throw new ArgumentException("username can't be null or empty");
            }
            if (ipAddress.Length != 4)
            {
                throw new ArgumentException("ipAddress should have four octets");
            }
            myUsername = username;
            myIPAddress = ipAddress;
            myMask = mask;
            myIsAllowed = isAllowed;
        }

        public override string ToString()
        {
            return myUsername + "|" + myIPAddress[0].ToString() + "." + myIPAddress[1].ToString() + "." + myIPAddress[2].ToString() + "." + myIPAddress[3].ToString() + "/" + myMask + "|" + (myIsAllowed?"allow":"deny");
        }


        public string UserName
        {
            get
            {
                return myUsername;
            }
        }

        public UInt16[] IPAddress
        {
            get
            {
                return myIPAddress;
            }
        }

        public UInt16 Mask
        {
            get
            {
                return myMask;
            }
        }
        public bool IsAllowed
        {
            get
            {
                return myIsAllowed;
            }
        }
    }
}
