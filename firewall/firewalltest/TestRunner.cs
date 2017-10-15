using System;
using firewalltest.UtilsTest;
using System.Diagnostics;
using System.Collections.Generic;
using System.IO;

namespace firewalltest
{
    class TestRunner
    {
        private static readonly string BASELINE = @"..\..\Baseline\testoutput.txt";
        private static readonly string FIREWALLEXE = @"..\..\..\firewall\bin\Debug\firewall.exe";
        private static readonly string command = @"..\..\Collateral\rules.txt F:\temp\firewall\firewall\firewall\firewalltest\Collateral\host";
        static void Main(string[] args)
        {
            RunUnitTests();
            
            string retMessage = String.Empty;
            retMessage = RunFireWallTest();
            Console.WriteLine(retMessage);

            bool isPassed = TestResult(retMessage);
            if (isPassed)
            {
                Console.WriteLine("Passed");
            }
            else
            {
                Console.WriteLine("Failed");
            }
            
        }

        private static bool IsNotNullOrEmpty(String s)
        {
            return !String.IsNullOrEmpty(s);
        }

        private static bool TestResult(string retMessage)
        {
            string[] lines = retMessage.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            int i = 0;
            lines = Array.FindAll(lines, IsNotNullOrEmpty);

            var set = new HashSet<String>(lines);
            foreach (string line in File.ReadLines(BASELINE))
            {
                if (!set.Contains(line))
                {
                    return false;
                }
                i++;
            }
            if (i != lines.Length)
            {
                return false;
            }
            return true;
        }

        private static string RunFireWallTest()
        {
            string retMessage;
            ProcessStartInfo startInfo = new ProcessStartInfo();
            Process p = new Process();

            startInfo.CreateNoWindow = true;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardInput = true;

            startInfo.UseShellExecute = false;
            startInfo.Arguments = command;
            startInfo.FileName = FIREWALLEXE;

            p.StartInfo = startInfo;
            p.Start();

            System.Threading.Thread.Sleep(1000);
            StreamWriter streamWriter = p.StandardInput;
            streamWriter.WriteLine("\n");

            p.WaitForExit();
            retMessage = p.StandardOutput.ReadToEnd();
            return retMessage;
        }

        private static void RunUnitTests()
        {
            ipparserTest.run();
        }
    }
}
