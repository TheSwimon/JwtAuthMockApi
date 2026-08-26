using JwtAuthMockApi.Data;
using JwtAuthMockApi.Entities;
using JwtAuthMockApi.Models;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthMockApi.Services
{
    public class AuthService(AppDbContext context) : IAuthService
    {
        public Task<string?> LoginAsync(UserDto request)
        {
            throw new NotImplementedException();
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
