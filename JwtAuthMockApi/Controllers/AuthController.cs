using JwtAuthMockApi.Entities;
using JwtAuthMockApi.Models;
using JwtAuthMockApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthMockApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IConfiguration configuration, IAuthService authService) : ControllerBase
    {
        private static User _user = new User();


        [HttpPost("register")]
        public async Task<ActionResult<User>> RegisterAsync(UserDto request)
        {
            var user = await authService.RegisterAsync(request);

            if (user == null)
            {
                return BadRequest("Username already exists");
            }

            return Ok(user);
        }


        [HttpPost("login")]
        public async Task<ActionResult<string>> LoginAsync(UserDto request)
        {
            var token = await authService.LoginAsync(request);

            if (token == null)
            {
                return BadRequest("Invalid credentials");
            }

            return Ok(token);
        }

        [Authorize]
        [HttpGet]
        public ActionResult AuthenticatedUsersOnlyEndpoint()
        {
            return Ok("You are authenticated");
        }
    }
}
