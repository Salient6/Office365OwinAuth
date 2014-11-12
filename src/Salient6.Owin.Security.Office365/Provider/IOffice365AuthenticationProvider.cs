using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Salient6.Owin.Security.Office365
{
    public interface IOffice365AuthenticationProvider
    {
        /// <summary>
        /// Invoked whenever Microsoft succesfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task Authenticated(Office365AuthenticatedContext context);
    }
}
