using JwtAuthMockApi.Data;
using JwtAuthMockApi.Entities;
using JwtAuthMockApi.Models;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthMockApi.Services
{
    public class AuthService(AppDbContext context, IConfiguration configuration) : IAuthService
    {
        public async Task<string?> LoginAsync(UserDto request)
        {
            var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);

            if (user == null)
            {
                return null;
            }

            var hasher = new PasswordHasher<User>();
            var result = hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);

            if (result == PasswordVerificationResult.Failed)
            {
                return null;
            }

            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, request.Username)
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

        public async Task<User?> RegisterAsync(UserDto request)
        {
            if (await context.Users.AnyAsync(u => u.Username == request.Username))
            {
                return null;
            }

            var newUser = new User();

            string hashedPassword = new PasswordHasher<User>()
                .HashPassword(newUser, request.Password);

            newUser.Username = request.Username;
            newUser.PasswordHash = hashedPassword;
            context.Add(newUser);
            await context.SaveChangesAsync();

            return newUser;
        }
    }
}
