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
            var result = await authService.LoginAsync(request);

            if (result == null)
            {
                return BadRequest("Invalid credentials");
            }

            return Ok(result);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDto>> RefreshToken(RefreshTokenRequestDto request)
        {
            var response = await authService.RefreshTokensAsync(request);

            if (response is null || response.AccessToken is null || response.RefreshToken is null)
            {
                return Unauthorized("Invalid refresh token");
            }

            return Ok(response);
        }



        [Authorize]
        [HttpGet]
        [Route("pleb-playground")]
        public ActionResult PlaygroundForPlebs()
        {
            return Ok("You are free to roll in dirt you dirty maggot");
        }



        [Authorize(Roles = "Admin")]
        [HttpGet]
        [Route("royal-chamber")]
        public ActionResult RoyalOnlyChamber()
        {
            return Ok("Welcome to the royal chamber, your honor");
        }

    }
}
