using JwtAuthMockApi.Entities;
using JwtAuthMockApi.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace JwtAuthMockApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private static User _user = new User();


        [HttpPost("register")]
        public ActionResult<User> Register(UserDto request)
        {
            string hashedPassword = new PasswordHasher<User>()
                .HashPassword(_user, request.Password);

            _user.Username = request.Username;
            _user.PasswordHash = hashedPassword;

            return Ok(_user);

        }


        [HttpPost("login")]
        public IActionResult Login(UserDto request)
        {
            if (_user.Username != request.Username)
            {
                return Unauthorized();
            }

            var hasher = new PasswordHasher<User>();
            var result = hasher.VerifyHashedPassword(_user, _user.PasswordHash, request.Password);

            if (result == PasswordVerificationResult.Failed)
            {
                return Unauthorized("Incorrect credentials");
            }

            return Ok(_user);
        }

        
    }
}
