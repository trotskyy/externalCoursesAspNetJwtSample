using AspNetIdentityAuthSample.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Web.Http;
using Microsoft.AspNet.Identity.Owin;
using System.Threading.Tasks;
using System.IdentityModel.Tokens;
using System.Text;
using System.Web.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AspNetIdentityAuthSample.Controllers
{
    [RoutePrefix("auth")]
    public class AuthController : ApiController
    {
        private UserManager<IdentityUser> UserManager =>
            Request.GetOwinContext().Get<UserManager<IdentityUser>>();

        private readonly HttpClient _httpClient;

        public AuthController()
        {
            // inject it
            _httpClient = new HttpClient();
        }

        [Route("sign-in")]
        [HttpPost]
        public async Task<IHttpActionResult> SignIn(SignInModel signInModel)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            Request.GetOwinContext().Authentication.SignIn();

            // get user from ASP.NET Identity DB
            // ...

            IdentityUser user = UserManager.Users.FirstOrDefault(u => u.UserName == signInModel.Login);
            if (user == null)
            {
                return Unauthorized();
            }

            string token = await IssueToken(user);

            return Ok(new { user = "Some user data from domain DB", token });
        }

        [Route("sign-up")]
        [HttpPost]
        public async Task<IHttpActionResult> SignUp([FromBody]SignUpModel signUpModel, [FromUri] bool addAsAdmin)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var newUser = new IdentityUser(signUpModel.Login);
            IdentityResult result = await UserManager.CreateAsync(newUser, signUpModel.Password);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors.Aggregate((agg, msg) => agg += "; " + msg));
            }

            // for demo purposes only! in real world scenarios such users should be created only by super admin e.g.
            if (addAsAdmin)
            {
                // roles should be extracted into some enum e.g.
                IdentityResult addToRoleResult = await UserManager.AddToRoleAsync(newUser.Id, "Admin");

                if (!addToRoleResult.Succeeded)
                {
                    // actually we should roll back all changes and give user meaningfull output
                    return BadRequest();
                }
            }

            // create user in Domain DB
            // ...

            string token = await IssueToken(newUser);

            return Ok(new { user = "Some user data from domain DB", token });
        }

        private async Task<string> IssueToken(IdentityUser identityUser)
        {
            string audience = WebConfigurationManager.AppSettings["jwt:aud"];
            string issuer = WebConfigurationManager.AppSettings["jwt:iss"];
            // the key upon wich HMAC signature will be created
            string key = WebConfigurationManager.AppSettings["jwt:hash_key"];


            //string key = "some randomly generated cryptographically good number";
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(key);
            var secret = Convert.ToBase64String(bytes);

            var now = DateTime.UtcNow;
            var securityKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Encoding.Default.GetBytes(secret));
            var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                securityKey,
                SecurityAlgorithms.HmacSha256Signature);

            var issuedAt = DateTime.Now.ToUniversalTime();
            var expiresAt = issuedAt.AddMinutes(5);

            IList<Claim> claims = await UserManager.GetClaimsAsync(identityUser.Id);
            
            if (identityUser.Roles.Count > 0)
            {
                IList<string> roles = await UserManager.GetRolesAsync(identityUser.Id);

                foreach (string role in roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }
            }

            var token = new JwtSecurityToken(issuer, 
                audience, 
                claims, 
                issuedAt,
                expiresAt, 
                signingCredentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
