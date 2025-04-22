using JwtAuthTemplate.Entities;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthTemplate.Data
{
    public class UserDbContext(DbContextOptions<UserDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users { get; set; }
    }
}
