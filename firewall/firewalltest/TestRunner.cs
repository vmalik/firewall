using System;
using firewalltest.UtilsTest;
using System.Diagnostics;

namespace firewalltest
{
    class TestRunner
    {
        private static readonly string FIREWALLEXE = @"F:\temp\firewall\firewall\firewall\firewall\bin\Debug\firewall.exe";
        private static readonly string command = @"F:\temp\firewall\input\rules.txt F:\temp\firewall\input\hosts";
        static void Main(string[] args)
        {
            //RunUnitTests();
            string retMessage = String.Empty;
            retMessage = RunFireWallTest();

            Console.WriteLine(retMessage);
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

            p.WaitForExit();
            retMessage = p.StandardOutput.ReadToEnd();
            return retMessage;
        }

        private static void RunUnitTests()
        {
            ipparserTest.run();
            IPmatchTest.run();
        }
    }
}
