using Microsoft.Owin;
using Microsoft.Owin.Security;
using Newtonsoft.Json.Linq;
using Salient6.Owin.Security.Office365.Utility;
using System;
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace Salient6.Owin.Security.Office365
{
    public abstract class Office365AuthenticationOptions : AuthenticationOptions
    {
        public Office365AuthenticationOptions() : base(Constants.DefaultAuthenticationType)
        {
            CallbackPath = new PathString(Constants.CallbackPath);
            ClientId = ConfigurationManager.AppSettings["ida:ClientID"];
            ClientSecret = ConfigurationManager.AppSettings["ida:Password"];
            AuthorizationEndpoint = ConfigurationManager.AppSettings["ida:AuthorizationUri"];
        }

        /// <summary>
        /// The API endpoint to load user Identity data from, with no trailing slash.
        /// </summary>
        public string ApiEndpoint { get; set; }

        /// <summary>
        /// The API endpoint to authorize against, with no trailing slash.
        /// </summary>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// The application callback path.
        /// </summary>
        public PathString CallbackPath { get; set; }

        // <summary>
        /// The application client ID assigned by the Microsoft authentication service.
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// The application client secret assigned by the Microsoft authentication service.
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// The Provider used for authentication.
        /// </summary>
        public IOffice365AuthenticationProvider Provider { get; set; }

        /// <summary>
        /// The Resource ID for the service, used to obtain a new access token or to retrieve an existing token from cache.
        /// </summary>
        public string ResourceId { get; set; }

        /// <summary>
        /// Gets or sets the AuthenticationType used when creating the <see cref="System.Security.Claims.ClaimsIdentity"/>.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        /// Data Protector for state data.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// Returns a URL through which a user can be authorized to access Office 365 APIs.
        /// After the authorization is complete, the user will be redirected back to the URL 
        ///     defined by the redirectTo parameter. This can be the same URL as the caller's URL
        ///     (e.g., Request.Url), or it can contain additional query-string parameters
        ///     (e.g., to restore state).
        /// "/common/oauth2/authorize?response_type=code&client_id={0}&resource={1}&redirect_uri={2}&state={3}";
        /// </summary>
        public virtual string GetAuthorizationUrl(string redirectTo, string state)
        {
            return String.Concat(AuthorizationEndpoint,
                        String.Format(CultureInfo.InvariantCulture,
                            Constants.AuthorizeEndPointFormat,
                            Uri.EscapeDataString(ClientId),
                            Uri.EscapeDataString(ResourceId),
                            Uri.EscapeDataString(redirectTo.ToString()),
                            Uri.EscapeDataString(state)));//stateCookieInfo.UniqueId));
        }

        /// <summary>
        /// Determines the format of the response string, and extract a human-readable error message
        /// from a response string.
        /// </summary>
        protected static string GetErrorMessage(string responseString, string[] jsonErrorPath, string[] xmlErrorPath)
        {
            switch (responseString.TrimStart().FirstOrDefault())
            {
                case '{':
                    return ParseJsonErrorMessage(jsonErrorPath, responseString);
                case '<':
                    return ParseXmlErrorMessage(xmlErrorPath, responseString);
                default:
                    throw new ArgumentException("Unrecognized format for the response.");
            }
        }

        /// <summary>
        /// Extracts a human-readable error message from the response string. If the format is not recognized,
        /// or if the path is not of the expected form, an exception can be thrown.
        /// </summary>
        internal abstract string ParseErrorMessage(string responseString);

        private static string ParseJsonErrorMessage(string[] path, string responseString)
        {
            JToken currentJsonNode = JObject.Parse(responseString);
            foreach (string nodeName in path)
            {
                currentJsonNode = currentJsonNode[nodeName];
            }
            return currentJsonNode.Value<string>();
        }

        private static string ParseXmlErrorMessage(string[] path, string responseString)
        {
            using (StringReader reader = new StringReader(responseString))
            {
                XDocument xmlDoc = XDocument.Load(reader);
                XNamespace xmlNamespace = xmlDoc.Root.Name.Namespace;
                XElement currentXmlNode = xmlDoc.Root;
                if (xmlDoc.Root.Name.LocalName != path.First())
                {
                    throw new Exception("Unexpected root node name: " + xmlDoc.Root.Name.LocalName);
                }
                foreach (string nodeName in path.Skip(1))
                {
                    currentXmlNode = currentXmlNode.Element(xmlNamespace + nodeName);
                }
                return currentXmlNode.Value;
            }
        }
    }
}
