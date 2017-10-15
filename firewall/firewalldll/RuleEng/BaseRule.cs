using System;

namespace firewall.RuleEng
{
    public abstract class BaseRule : IRule
    {
        private string myUsername;
        private bool myIsAllowed = false;

        private static readonly string ALLOW = "allow";
        private static readonly string DENY = "deny";

        public BaseRule(string username, bool isAllowed)
        {
            if (String.IsNullOrEmpty(username))
            {
                throw new ArgumentException("username can't be null or empty");
            }
            myUsername = username;
            myIsAllowed = isAllowed;
        }

        
        protected static bool TryParseIsAllowed(string field, out bool isAllowed)
        {
            isAllowed = false;
            if (String.Equals(field, ALLOW, StringComparison.OrdinalIgnoreCase))
            {
                isAllowed = true;
                return true;
            }
            else if (String.Equals(field, DENY, StringComparison.OrdinalIgnoreCase))
            {
                isAllowed = false;
                return true;
            }
            else
            {
                return false;
            }
        }
        public string UserName
        {
            get
            {
                return myUsername;
            }
        }
        public bool IsAllowed()
        {
            return myIsAllowed;
        }
    }
}
