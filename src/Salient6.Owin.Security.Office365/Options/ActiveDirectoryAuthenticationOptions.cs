using Salient6.Owin.Security.Office365.Utility;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Salient6.Owin.Security.Office365
{
    public class ActiveDirectoryAuthenticationOptions : Office365AuthenticationOptions
    {
        public ActiveDirectoryAuthenticationOptions()
        {
            // For Active Directory, the resource ID and API Endpoint are static for the public O365 cloud.
            ApiEndpoint = Constants.ActiveDirectory.ApiEndpoint;
            ResourceId = Constants.ActiveDirectory.ResourceId;
        }

        internal override string ParseErrorMessage(string responseString)
        {
            string[] jsonErrorPath = { "odata.error", "message", "value" };
            string[] xmlErrorPath = { "error", "message" };
            return GetErrorMessage(responseString, jsonErrorPath, xmlErrorPath);
        }
    }
}
