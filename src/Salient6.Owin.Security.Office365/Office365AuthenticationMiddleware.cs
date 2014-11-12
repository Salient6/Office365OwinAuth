using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using System;
using System.Globalization;
using System.Net.Http;

namespace Salient6.Owin.Security.Office365
{
    public class Office365AuthenticationMiddleware : AuthenticationMiddleware<Office365AuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public Office365AuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, Office365AuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.ClientId))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "ClientId must be provided"));
            }
            if (string.IsNullOrWhiteSpace(Options.ClientSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "ClientSecret must be provided"));
            }
            if (string.IsNullOrWhiteSpace(Options.AuthenticationType))
            {
                Options.AuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            if (options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(Office365AuthenticationMiddleware).FullName,
                    options.AuthenticationType);

                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (options.Provider == null)
            {
                options.Provider = new Office365AuthenticationProvider();
            }


            //if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            //{
            //    Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            //}

            //_httpClient = new HttpClient(ResolveHttpMessageHandler(Options));
            //_httpClient.Timeout = Options.BackchannelTimeout;
            //_httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 M
            _logger = app.CreateLogger<Office365AuthenticationMiddleware>();
 
        }

        protected override AuthenticationHandler<Office365AuthenticationOptions> CreateHandler()
        {
            return new Office365AuthenticationHandler(_httpClient, _logger);
        }
    }
}
