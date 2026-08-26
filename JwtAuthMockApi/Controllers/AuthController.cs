using JwtAuthMockApi.Entities;
using JwtAuthMockApi.Models;
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
    public class AuthController(IConfiguration configuration) : ControllerBase
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
        public ActionResult<string> Login(UserDto request)
        {
            if (_user.Username != request.Username)
            {
                return BadRequest("Incorrect Credentials");
            }

            var hasher = new PasswordHasher<User>();
            var result = hasher.VerifyHashedPassword(_user, _user.PasswordHash, request.Password);

            if (result == PasswordVerificationResult.Failed)
            {
                return Unauthorized("Incorrect credentials");
            }

            var token = CreateToken(_user);

            return Ok(token);
        }


        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JwtSettings:SecretKey"]!));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration["AppSettings:Issuer"],
                audience: configuration["AppSettings:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }

    }
}
