using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Salient6.Owin.Security.Office365.Utility
{
    internal static class Constants
    {
        internal const string AuthorizeEndPointFormat = "/common/oauth2/authorize?response_type=code&client_id={0}&resource={1}&redirect_uri={2}&state={3}";
        internal const string DefaultAuthenticationType = "Office365";
        internal const string CallbackPath = "/signin-office365";
        internal const string OAuthRequestStateCookiePrefix = "WindowsAzureActiveDirectoryOAuthRequestState#";

        //Authorization Query Strings
        internal const string Code = "code";
        internal const string Error = "error";
        internal const string ErrorDescription = "error_description";
        internal const string State = "state";

        internal static class ActiveDirectory
        {
            /// <summary>
            /// Location of the user's Identity information
            /// </summary>
            internal const string ResourceId = "https://graph.windows.net/";
            internal const string ApiEndpoint = "https://graph.windows.net";
        }
    }
}
