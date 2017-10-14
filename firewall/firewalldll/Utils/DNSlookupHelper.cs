using System;
using System.Collections.Generic;
using System.Runtime.Caching;
using System.Linq;

namespace firewall.Utils
{
    public class DNSlookupHelper
    {
        private static Dictionary<string, string> IPtoHostMap;
        private static readonly double cacheExpirationInMinutes = 5;

        static DNSlookupHelper()
        {
            IPtoHostMap = new Dictionary<string, string>();
            
            IPtoHostMap.Add("91.122.1.2", "www.msn.com");
            IPtoHostMap.Add("91.122.1.3", "www.microsoft.com");

        }
        private static string lookupHost(string ipAddress)
        {
            string host;
            //make it slow
            System.Threading.Thread.Sleep(200);
            if (IPtoHostMap.TryGetValue(ipAddress, out host))
            {
                return host;
            }
            return null;
        }
        public static string lookupCachedHost(UInt16[] ipAddress)
        {
            ObjectCache cache = MemoryCache.Default;
            string key = string.Join(".", ipAddress.Select(x => x.ToString()).ToArray());
            string cachedObject = (string)cache[key];
            if (cachedObject == null)
            {
                CacheItemPolicy policy = new CacheItemPolicy();
                policy.AbsoluteExpiration = DateTimeOffset.Now.AddMinutes(cacheExpirationInMinutes);
                cachedObject = lookupHost(key);
                if (cachedObject == null)
                {
                    cachedObject = "";
                }
                cache.Set(key, cachedObject, policy);
            }
            return cachedObject;
        }
    }
}
