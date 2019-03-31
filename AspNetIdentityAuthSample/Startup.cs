using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.AspNet.Identity.EntityFramework;
using Owin;
using Microsoft.Owin.Security.Jwt;
using System;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Cors;
using System.Text;
using System.Web.Configuration;

namespace AspNetIdentityAuthSample
{
    // startup class for OWIN middleware
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.CreatePerOwinContext(() => new IdentityDbContext());

            app.CreatePerOwinContext<UserManager<IdentityUser>>((options, context) =>
            {
                var dbContext = context.Get<IdentityDbContext>();
                var userStore = new UserStore<IdentityUser>(dbContext);

                return new UserManager<IdentityUser>(userStore);
            });


            app.UseCors(CorsOptions.AllowAll);

            string audience = WebConfigurationManager.AppSettings["jwt:aud"];
            string issuer = WebConfigurationManager.AppSettings["jwt:iss"];
            // the key upon wich HMAC signature will be created
            string key = WebConfigurationManager.AppSettings["jwt:hash_key"];
            //var audience = "http://localhost:4200"; // your Angular app
            //var issuer = "https://localhost:17579"; // your web API

            
            //string key = "some randomly generated cryptographically good number";
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(key);
            var secret = Convert.ToBase64String(bytes);

            var now = DateTime.UtcNow;
            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(secret));
            var signingCredentials = new SigningCredentials(
                securityKey,
                SecurityAlgorithms.HmacSha256Signature);



            app.UseJwtBearerAuthentication(
                new JwtBearerAuthenticationOptions
                {
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKey = signingCredentials.Key,

                        ValidIssuer = issuer,
                        ValidateIssuer = true,

                        ValidAudience = audience,
                        ValidateAudience = true,

                        ValidateLifetime = true
                    },
                }
            );
        }
    }
}