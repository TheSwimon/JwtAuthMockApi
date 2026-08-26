using JwtAuthMockApi.Entities;
using JwtAuthMockApi.Models;

namespace JwtAuthMockApi.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDto request);

        Task<string?> LoginAsync(UserDto request);
    }
}
