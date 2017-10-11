using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace firewall.Utils
{
    public class PacketParser
    {
        public static bool TryParse(string line, out Packet packet)
        {
            packet = null;
            //System.Console.WriteLine(line);
            string[] fields = line.Split('|');
            if (fields.Length != 2)
            {
                return false;
            }
            UInt16[] ipAddress = IPParser.ParseIPAddress(fields[1]);
            if (ipAddress == null)
            {
                return false;
            }
            packet = new Packet(fields[0], ipAddress);
            return true;
        }
    }
}
