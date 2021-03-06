﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using firewall.RuleEng;

namespace firewall
{
    public class MyMain
    {
        public static void Main(string[] args)
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
                Console.Read();
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
