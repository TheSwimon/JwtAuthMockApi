using JwtAuthMockApi.Entities;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthMockApi.Data
{
    public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users { get; set; }

    }
}
