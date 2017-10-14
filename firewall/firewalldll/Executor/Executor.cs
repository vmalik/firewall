using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using firewall.RuleEng;

namespace firewall.RuleEng
{
    public class Executor
    {
        private string myRuleFilePath;
        private string myHostFilesPath;
        private RuleEngine myRuleEngine;
        private Dictionary<string, ManualResetEvent> myResetEvents = new Dictionary<string, ManualResetEvent>();

        SemaphoreSlim packetProcessThreadThrottler = new SemaphoreSlim(2,2);
        SemaphoreSlim fileProcessThreadThrottler = new SemaphoreSlim(5,5);

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
                List<ManualResetEvent> eventsToWait = new List<ManualResetEvent>();
                foreach (string file in Directory.EnumerateFiles(myHostFilesPath, "*", SearchOption.TopDirectoryOnly))
                {
                    ProcessFileAsync(file);
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

        async private void ProcessFileAsync(string file)
        {
            await packetProcessThreadThrottler.WaitAsync();
            await Task.Run(() => ProcessFile(file));
            packetProcessThreadThrottler.Release();
        }

        private void ProcessFile(string file)
        {
            //Console.WriteLine("Processing " + file + "in thread : " + Thread.CurrentThread.ManagedThreadId);
            foreach (string line in File.ReadLines(file))
            {
                //<host-name>: <username> access to <ip-address> was <allowed/denied>.
                ProcessPacket(file, line);
            }
            if (myResetEvents.ContainsKey(file))
            {
                ManualResetEvent rEvent;
                myResetEvents.TryGetValue(file, out rEvent);
                rEvent.Set();
            }
        }

        async private void ProcessPacket(string file, string line)
        {
            Packet packet = null;

            if (PacketParser.TryParse(line, out packet))
            {
                await packetProcessThreadThrottler.WaitAsync();
                // Yield and call rule-engine asynchronously
                bool isAllowed = await Task.Run(() => myRuleEngine.IsAllowed(packet));
                packetProcessThreadThrottler.Release();
                if (isAllowed)
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
