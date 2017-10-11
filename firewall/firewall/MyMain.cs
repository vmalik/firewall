using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using firewall.Utils;

namespace firewall
{
    class MyMain
    {
        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                System.Console.WriteLine("Usage: firewall.exe [rulefile] [HostFilesPath]");
                return;
            }
            //System.Console.WriteLine("Arguments: " + args[0] + " " + args[1]);

            try
            {
                Executor exec = new Executor(args[0], args[1]);
                exec.execute();
            }
            catch (ArgumentException e)
            {
                System.Console.WriteLine("Exception: " + e.ToString());
            }
            catch (Exception e)
            {
                System.Console.WriteLine("Exception: " + e.ToString());
                throw e;
            }
        }
    }
}
