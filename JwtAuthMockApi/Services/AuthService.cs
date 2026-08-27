using Azure.Core;
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
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthMockApi.Services
{
    public class AuthService(AppDbContext context, IConfiguration configuration) : IAuthService
    {
        public async Task<TokenResponseDto?> LoginAsync(UserDto request)
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

            return await CreateTokenResponse(user);

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


        public async Task<TokenResponseDto?> RefreshTokensAsync(RefreshTokenRequestDto request)
        {
            var user = await ValidateRefreshTokenAsync(request);

            if (user is null)
            {
                return null;
            }

            return await CreateTokenResponse(user);


        }


        private async Task<User?> ValidateRefreshTokenAsync(RefreshTokenRequestDto request)
        {
            var user = await context.Users.FindAsync(request.UserId);

            if (user is null || user.RefreshToken != request.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return null;
            }

            return user;
        }


        private async Task<TokenResponseDto?> CreateTokenResponse(User user)
        {
            return new TokenResponseDto { AccessToken = GenerateJwtToken(user), RefreshToken = await GenerateAndSaveRefreshTokenAsync(user) };
        }


        private async Task<string> GenerateAndSaveRefreshTokenAsync(User user)
        {
            var refreshToken = GenerateRefreshToken();


            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await context.SaveChangesAsync();

            return refreshToken;
        }

        private string GenerateRefreshToken()
        {
            var bytes = new byte[32];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);


            return Convert.ToBase64String(bytes) ;
        }

   

        private string GenerateJwtToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.Role)
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
