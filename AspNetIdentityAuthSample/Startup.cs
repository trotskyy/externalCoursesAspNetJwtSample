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

namespace AspNetIdentityAuthSample
{ 
    // startup class for OWIN middleware
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.CreatePerOwinContext(() => new IdentityDbContext());
            //app.CreatePerOwinContext<UserManager<IdentityUser>>(UserManager<IdentityUser>.)
            app.CreatePerOwinContext<UserManager<IdentityUser>>((options, context) =>
            {
                var dbContext = context.Get<IdentityDbContext>();
                var userStore = new UserStore<IdentityUser>(dbContext);

                return new UserManager<IdentityUser>(userStore);
            });


            app.UseCors(CorsOptions.AllowAll);

            var audience = "http://localhost:4200"; // your Angular app
            var issuer = "https://localhost:17579"; // your web API

            // the key upon wich HMAC signature will be created
            string key = "some randomly generated cryptographically good number";
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(key);
            var secret = Convert.ToBase64String(bytes);

            app.UseJwtBearerAuthentication(
                new JwtBearerAuthenticationOptions
                {
                    AuthenticationMode = AuthenticationMode.Active,
                    AllowedAudiences = new [] { audience },
                    IssuerSecurityKeyProviders = new IIssuerSecurityKeyProvider[]
                    {
                        new SymmetricKeyIssuerSecurityKeyProvider(issuer, secret)
                    },

                    // if needed, configure other options
                    //TokenValidationParameters = new TokenValidationParameters
                    //{
                        
                    //}
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
        public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            //if (context.Password != "123" || context.UserName != "test")
            //{
            //    context.SetError("invalid_grant", "The user name or password is incorrect");
            //    context.Rejected();
            //    return Task.FromResult<object>(null);
            //}

            var user = context.OwinContext.Get<IdentityDbContext>().Users.FirstOrDefault(u => u.UserName == context.UserName);
            if (!context.OwinContext.Get<UserManager<IdentityUser>>().CheckPassword(user, context.Password))
            {
                context.SetError("invalid_grant", "The user name or password is incorrect");
                context.Rejected();
                return Task.FromResult<object>(null);
            }

            //var user = new IdentityUser(context.UserName);

            //var user = context.OwinContext.Get<BooksContext>().Users.FirstOrDefault(u => u.UserName == context.UserName);
            //if (!context.OwinContext.Get<BookUserManager>().CheckPassword(user, context.Password))
            //{
            //    context.SetError("invalid_grant", "The user name or password is incorrect");
            //    context.Rejected();
            //    return Task.FromResult<object>(null);
            //}

            var ticket = new AuthenticationTicket(SetClaimsIdentity(context, user), new AuthenticationProperties());
            context.Validated(ticket);

            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
            return Task.FromResult<object>(null);
        }

        private static ClaimsIdentity SetClaimsIdentity(OAuthGrantResourceOwnerCredentialsContext context, IdentityUser user)
        {
            var identity = new ClaimsIdentity("JWT");
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            identity.AddClaim(new Claim("sub", context.UserName));

            //var userRoles = context.OwinContext.Get<BookUserManager>().GetRoles(user.Id);
            //foreach (var role in userRoles)
            //{
            //    identity.AddClaim(new Claim(ClaimTypes.Role, role));
            //}

            return identity;
        }
    }
}