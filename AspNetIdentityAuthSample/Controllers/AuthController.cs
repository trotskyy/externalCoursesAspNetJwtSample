using AspNetIdentityAuthSample.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using Microsoft.AspNet.Identity.Owin;
using System.Threading.Tasks;
using Microsoft.Owin;

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

            string token = await GetToken(signInModel.Login, signInModel.Password);

            return Ok(new { user = "Some user data from domain DB", token });
        }

        [Route("sign-up")]
        [HttpPost]
        public async Task<IHttpActionResult> SignUp(SignUpModel signUpModel)
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

            // create user in Domain DB
            // ...

            string token = await GetToken(signUpModel.Login, signUpModel.Password);

            return Ok(new { user = "Some user data from domain DB", token });
        }

        private async Task<string> GetToken(string userName, string password)
        {
            //_httpClient.DefaultRequestHeaders.Add("Content-Type", "application/x-www-form-urlencoded");
            string tokenEndpoint = "http://" + Request.RequestUri.Authority + "/token";

            var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
            //request.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "username", userName },
                { "password", password },
                { "grant_type", "password" },
            });
            request.Content.Headers.ContentType
                = new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");

            HttpResponseMessage tokenResponse = await _httpClient.SendAsync(request);

            string token = await tokenResponse.Content.ReadAsStringAsync();

            return token;
        }
    }
}
