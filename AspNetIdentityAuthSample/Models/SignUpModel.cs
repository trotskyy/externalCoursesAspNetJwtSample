using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AspNetIdentityAuthSample.Models
{
    public class SignUpModel
    {
        public string Login { get; set; }

        public string Password { get; set; }

        public string Name { get; set; }
    }
}