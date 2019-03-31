using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.AspNet.Identity.EntityFramework;
using Owin;
using Microsoft.Owin.Security.Jwt;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Owin.Security;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Security.OAuth;
using Thinktecture.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;
using System.Security.Claims;
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

            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new Microsoft.Owin.PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(5),
                Provider = new CustomOAuthProvider(),
                AccessTokenFormat = new CustomJwtFormat(issuer, secret, audience)
            });
        }
    }

    public class CustomJwtFormat : ISecureDataFormat<AuthenticationTicket>
    {
        private readonly string _issuer;
        private readonly string _secret;
        private readonly string _audience;

        public CustomJwtFormat(string issuer, string secret, string audience)
        {
            _issuer = issuer;
            _secret = secret;
            _audience = audience;
        }

        public string Protect(AuthenticationTicket data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            var now = DateTime.UtcNow;
            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(_secret));
            var signingCredentials = new SigningCredentials(
                securityKey,
                SecurityAlgorithms.HmacSha256Signature);

            DateTimeOffset? issuedAt = data.Properties.IssuedUtc;
            DateTimeOffset? expiresAt = data.Properties.ExpiresUtc;


            var token = new JwtSecurityToken(_issuer, _audience, data.Identity.Claims, issuedAt.Value.UtcDateTime,
                expiresAt.Value.UtcDateTime, signingCredentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public AuthenticationTicket Unprotect(string protectedText)
        {
            throw new NotImplementedException();
        }
    }

    public class CustomOAuthProvider : OAuthAuthorizationServerProvider
    {
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            var user = context.OwinContext.Get<IdentityDbContext>().Users.FirstOrDefault(u => u.UserName == context.UserName);
            if (!context.OwinContext.Get<UserManager<IdentityUser>>().CheckPassword(user, context.Password))
            {
                context.SetError("invalid_grant", "The user name or password is incorrect");
                context.Rejected();
                return;
            }

            ClaimsIdentity claimsIdentity = await SetClaimsIdentity(context, user);

            var ticket = new AuthenticationTicket(claimsIdentity, new AuthenticationProperties());
            context.Validated(ticket);
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
            return Task.FromResult<object>(null);
        }

        private static async Task<ClaimsIdentity> SetClaimsIdentity(OAuthGrantResourceOwnerCredentialsContext context, IdentityUser user)
        {
            var identity = new ClaimsIdentity("JWT");
            identity.AddClaim(new Claim("sub", context.UserName));

            if (user.Roles != null)
            {
                IList<string> roles = await context.OwinContext
                    .GetUserManager<UserManager<IdentityUser>>()
                    .GetRolesAsync(user.Id);

                foreach (string role in roles)
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, role));
                }
            }

            return identity;
        }
    }
}