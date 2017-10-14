using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace firewall.RuleEng
{
    public class Packet
    {
        private string myUserName;
        private UInt16[] myIPAddress = new UInt16[4];
        
        public Packet(string username, UInt16[] ipAddress)
        {
            if (String.IsNullOrEmpty(username))
            {
                throw new ArgumentException("username can't be null or empty");
            }
            myUserName = username;
            myIPAddress = ipAddress;
        }

        public override string ToString()
        {
            return myUserName + "|" + myIPAddress[0].ToString() + "." + myIPAddress[1].ToString() + "." + myIPAddress[2].ToString() + "." + myIPAddress[3].ToString();
        }

        public string UserName
        {
            get
            {
                return myUserName;
            }
        }

        public string IPAddressAsString
        {
            get
            {
                return myIPAddress[0] + "." + myIPAddress[1] + "." + myIPAddress[2] + "." + myIPAddress[3];
            }
        }

        public UInt16[] IPAddress
        {
            get
            {
                return myIPAddress;
            }
        }
    }
}
