using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Security.Claims;

namespace Salient6.Owin.Security.Office365
{
    public class Office365AuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="Office365AuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">The access token provided by the Microsoft authentication service</param>
        /// <param name="refreshToken">The refresh token provided by Microsoft authentication service</param>
        /// <param name="expires">Seconds until expiration</param>
        public Office365AuthenticatedContext(IOwinContext context, AuthenticationResult result)// JObject user, string accessToken,  string refreshToken, string expires)
            : base(context)
        {
            if (result == null)
            {
                throw new ArgumentNullException("result");
            }

            User = result.UserInfo;
            AccessToken = result.AccessToken;
            RefreshToken = result.RefreshToken;

            ExpiresIn = result.ExpiresOn;

            JToken userId = User.UniqueId;//["id"];
            //if (userId == null)
            //{
            //    throw new ArgumentException("Missing UserId", "user");
            //}

            Id = userId.ToString();
            Name = User.DisplayableId;// PropertyValueIfExists("name", userAsDictionary);
            FirstName = User.GivenName;// PropertyValueIfExists("first_name", userAsDictionary);
            LastName = User.FamilyName;// PropertyValueIfExists("last_name", userAsDictionary);
            Email = User.DisplayableId;
            //if (userAsDictionary.ContainsKey("emails"))
            //{
            //    JToken emailsNode = user["emails"];
            //    foreach (var childAsProperty in emailsNode.OfType<JProperty>().Where(childAsProperty => childAsProperty.Name == "preferred"))
            //    {
            //        Email = childAsProperty.Value.ToString();
            //    }
            //}
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        public UserInfo User { get; private set; }

        /// <summary>
        /// Gets the access token provided by the Office365 authenication service
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the refresh token provided by Office365 authentication service
        /// </summary>
        /// <remarks>
        /// Refresh token is only available when wl.offline_access is request.
        /// Otherwise, it is null.
        /// </remarks>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the Office365 access token expiration time
        /// </summary>
        public DateTimeOffset ExpiresIn { get; set; }

        /// <summary>
        /// Gets the Microsoft Account user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the user first name
        /// </summary>
        public string FirstName { get; private set; }

        /// <summary>
        /// Gets the user last name
        /// </summary>
        public string LastName { get; private set; }

        /// <summary>
        /// Gets the user email address
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
    }
}
