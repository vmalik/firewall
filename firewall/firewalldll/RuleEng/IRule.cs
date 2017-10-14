using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace firewall.RuleEng
{
    public interface IRule
    {
        bool IsAllowed();
    }
}
