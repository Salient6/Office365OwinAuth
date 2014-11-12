using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Salient6.Owin.Security.Office365
{
    #region Private classes

    /// <summary>
    /// Data structure for holding the Office365 state in a cookie during an Authentication request.
    /// </summary>
    internal class Office365StateCookieInfo
    {
        public string UniqueId { get; set; }
        public string ResourceId { get; set; }
        public string RedirectTo { get; set; }
    }
    #endregion
}
