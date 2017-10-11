using System;
using System.IO;
using System.Threading;
using firewall.Utils;

namespace firewall.Utils
{
    public class Executor
    {
        private string myRuleFilePath;
        private string myHostFilesPath;
        private RuleEngine myRuleEngine;

        public Executor(string ruleFilePath, string hostFilePath)
        {
            if (String.IsNullOrEmpty(ruleFilePath))
            {
                throw new ArgumentException("ruleFilePath can't be null or empty");
            }
            if (String.IsNullOrEmpty(hostFilePath))
            {
                throw new ArgumentException("ruleFilePath can't be null or empty");
            }
            myRuleFilePath = ruleFilePath;
            myHostFilesPath = hostFilePath;
            myRuleEngine = new RuleEngine(myRuleFilePath);
        }

        public void execute()
        {
            try
            {
                foreach (string file in Directory.EnumerateFiles(myHostFilesPath, "*", SearchOption.TopDirectoryOnly))
                {
                    (new Thread(() => ProcessFile(file))).Start();
                    //ProcessFile(file);
                }
            }
            catch (UnauthorizedAccessException Ex)
            {
                Console.WriteLine(Ex.Message);
            }
            catch (PathTooLongException PathEx)
            {
                Console.WriteLine(PathEx.Message);
            }

        }

        public void ProcessFile(Object ofile)
        {
            string file = (string)ofile;
            foreach (string line in File.ReadLines(file))
            {
                //<host-name>: <username> access to <ip-address> was <allowed/denied>.
                Packet packet = null;
                if (PacketParser.TryParse(line, out packet))
                {
                    if (myRuleEngine.IsAllowed(packet))
                    {
                        Console.WriteLine(Path.GetFileName(file) + ": " + packet.UserName + " access to " + packet.IPAddressAsString + " was allowed");
                    }
                    else
                    {
                        Console.WriteLine(Path.GetFileName(file) + ": " + packet.UserName + " access to " + packet.IPAddressAsString + " was denied");
                    }
                }
            }
        }
    }
}
