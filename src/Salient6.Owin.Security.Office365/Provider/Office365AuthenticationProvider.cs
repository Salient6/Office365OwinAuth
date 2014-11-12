using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Salient6.Owin.Security.Office365
{
    public class Office365AuthenticationProvider : IOffice365AuthenticationProvider
    {
        public Office365AuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<Office365AuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Invoked whenever Office365 succesfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(Office365AuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }
    }
}
