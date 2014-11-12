using Owin;

namespace Salient6.Owin.Security.Office365
{
    public static class Office365AuthenticationExtension
    {
        public static IAppBuilder UseOffice365Authentication(this IAppBuilder app, Office365AuthenticationOptions options)
        {
            return app.Use(typeof(Office365AuthenticationMiddleware), app, options);
        }
    }
}
