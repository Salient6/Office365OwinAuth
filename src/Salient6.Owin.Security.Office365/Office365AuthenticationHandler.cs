using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Salient6.Owin.Security.Office365.Utility;
using System;
using System.Globalization;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Salient6.Owin.Security.Office365
{
    class Office365AuthenticationHandler : AuthenticationHandler<Office365AuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public Office365AuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            if(String.IsNullOrEmpty(Request.Query.ToString()))
            {
                return null;
            }
            string code = Request.Query.Get(Constants.Code);
            string error = Request.Query.Get(Constants.Error);
            string errorDescription = Request.Query.Get(Constants.ErrorDescription);
            string state = Request.Query.Get(Constants.State);
            string authCookieName = Constants.OAuthRequestStateCookiePrefix + state;
            // NOTE: In production, OAuth must be done over a secure HTTPS connection.
            if (Request.Uri.Scheme != "https" && !Request.Uri.IsLoopback)
            {
                const string message = "Invalid URL. Please run the app over a secure HTTPS connection.";
                LogErrorMessage(message, message + " URL: " + Request.Uri.ToString());
                return null;
            }

            // Ensure that there is a state cookie on the the request.
            //string stateCookie = Request.Cookies[authCookieName];
            //if (String.IsNullOrEmpty(stateCookie))
            //{
            //    //Office365Cache.RemoveAllFromCache();
            //    const string message = "An authentication error has occurred. Please return to the previous page and try again.";
            //    string errorDetail = "Missing OAuth state cookie." + " URL: " + Request.Uri.ToString();
            //    LogErrorMessage(message, errorDetail);
            //    return null;
            //}

            const string genericAuthenticationErrorMessage = "An authentication error has occurred.";

            //// Retrieve the unique ID from the saved cookie, and compare it with the state parameter returned by 
            ////     the Azure Active Directory Authorization endpoint:
            //Office365StateCookieInfo stateCookieInfo = JsonConvert.DeserializeObject<Office365StateCookieInfo>(stateCookie);
            //if (stateCookieInfo.UniqueId != state)
            //{
            //    // State is mismatched, error
            //    //Office365Cache.RemoveAllFromCache();
            //    string errorDetail = "OAuth state cookie mismatch." + " URL: " + Request.Uri.ToString();
            //    LogErrorMessage(genericAuthenticationErrorMessage, errorDetail);
            //    return null;
            //}

            //Response.Cookies.Delete(authCookieName);

            // Handle error codes returned from the Authorization Server, if any:
            if (error != null)
            {
                //Office365Cache.RemoveAllFromCache();
                LogErrorMessage(genericAuthenticationErrorMessage, error + ": " + errorDescription + " URL: " + Request.Uri.ToString());
                return null;
            }

            // If still here, redeem the authorization code for an access token:
            try
            {
                AuthenticationProperties properties = null;
                ClientCredential credential = new ClientCredential(Options.ClientId, Options.ClientSecret);
                string authority = String.Concat(Options.AuthorizationEndpoint, "/common");
                AuthenticationContext authContext = new AuthenticationContext(authority);
                AuthenticationResult result = authContext.AcquireTokenByAuthorizationCode(code, new Uri(Request.Uri.GetLeftPart(UriPartial.Path)), credential);
                properties = Options.StateDataFormat.Unprotect(state);
                var context = new Office365AuthenticatedContext(Context, result);

                ClaimsIdentity identity = new ClaimsIdentity(
                    new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, result.UserInfo.UniqueId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim(ClaimTypes.Name, result.UserInfo.DisplayableId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType)
                    },
                    "ApplicationCookie", /*Options.AuthenticationType,*/
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                await Options.Provider.Authenticated(context);

                //return Redirect(stateCookieInfo.RedirectTo);
                return new AuthenticationTicket(identity, properties);
            }
            catch (Exception ex)//ActiveDirect ActiveDirectoryAuthenticationException ex)
            {
                LogErrorMessage(genericAuthenticationErrorMessage, "URL: " + Request.Uri.ToString() + " Exception: " + ex.ToString());
                return null;
            }

            return null;// Task.FromResult(new AuthenticationTicket(identity, properties));
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

                // Only react to 401 if there is an authentication challenge for the authentication
                // type of this handler.
                if (challenge != null)
                {
                    var state = challenge.Properties;

                    string requestPrefix = String.Concat(Request.Scheme, "://", Request.Host, Options.CallbackPath);

                    if (string.IsNullOrEmpty(state.RedirectUri))
                    {
                        state.RedirectUri = "/";//Request.Uri.ToString();
                    }
                    var stateString = Options.StateDataFormat.Protect(state);

                    string authorizationEndpoint = Options.GetAuthorizationUrl(requestPrefix, stateString);

                    Response.Redirect(authorizationEndpoint);//WebUtilities.AddQueryString(Options.CallbackPath.Value, "state", stateString));
                }
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            // This is always invoked on each request. For passive middleware, only do anything if this is
            // for our callback path when the user is redirected back from the authentication provider.
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                var ticket = await AuthenticateAsync();

                if (ticket != null)
                {
                    Context.Authentication.SignIn(ticket.Properties, ticket.Identity);

                    Response.Redirect(ticket.Properties.RedirectUri);

                    // Prevent further processing by the owin pipeline.
                    return true;
                }
            }
            // Let the rest of the pipeline run.
            return false;
        }

        /// <summary>
        /// Send an HTTP request, with authorization. If the request fails due to an unauthorized exception,
        ///     this method will try to renew the access token in serviceInfo and try again.
        /// </summary>
        //private static async Task<HttpResponseMessage> SendRequestAsync(Office365ServiceInfo serviceInfo, HttpClient client, Func<HttpRequestMessage> requestCreator)
        //{
        //    using (HttpRequestMessage request = requestCreator.Invoke())
        //    {
        //        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", serviceInfo.AccessToken);
        //        request.Headers.UserAgent.Add(new ProductInfoHeaderValue(AppPrincipalId, String.Empty));
        //        HttpResponseMessage response = await client.SendAsync(request);

        //        // Check if the server responded with "Unauthorized". If so, it might be a real authorization issue, or 
        //        //     it might be due to an expired access token. To be sure, renew the token and try one more time:
        //        if (response.StatusCode == HttpStatusCode.Unauthorized)
        //        {
        //            Office365Cache.GetAccessToken(serviceInfo.ResourceId).RemoveFromCache();
        //            serviceInfo.AccessToken = GetAccessTokenFromRefreshToken(serviceInfo.ResourceId);

        //            // Create and send a new request:
        //            using (HttpRequestMessage retryRequest = requestCreator.Invoke())
        //            {
        //                retryRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", serviceInfo.AccessToken);
        //                retryRequest.Headers.UserAgent.Add(new ProductInfoHeaderValue(AppPrincipalId, String.Empty));
        //                response = await client.SendAsync(retryRequest);
        //            }
        //        }

        //        // Return either the original response, or the response from the second attempt:
        //        return response;
        //    }
        //}

        /// <summary>
        /// A static method that routes errors to a single centralized error-handler.
        /// This method will attempt to extract a human-readable error from the response string,
        /// based on the the format of the data and the error handling scheme of the service.
        /// </summary>
        private void LogErrorMessage(Office365AuthenticationOptions options, string responseString)
        {
            string message, errorDetails;
            try
            {
                message = options.ParseErrorMessage(responseString);
                errorDetails = responseString;
            }
            catch (Exception e)
            {
                message = "An unexpected error has occurred.";
                errorDetails = "Exception when parsing response string: " + e.ToString() + "\n\nResponse string was " + responseString;
            }
            LogErrorMessage(message, errorDetails);
        }

        /// <summary>
        /// A static method that routes errors to a single centralized error-handler.
        /// This method will attempt to extract a human-readable error from the response string,
        /// based on the the format of the data and the error handling scheme of the service.
        /// </summary>
        private void LogErrorMessage(string message, string errorDetails)
        {
            _logger.WriteError(String.Concat(message, errorDetails));
        }
    }
}
