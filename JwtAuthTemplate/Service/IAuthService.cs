using JwtAuthTemplate.Entities;
using JwtAuthTemplate.Models;

namespace JwtAuthTemplate.Service
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDto request);
        Task<TokenResponseDto?> LoginAsync(UserDto request);
        Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request);
        Task<bool> VerifyEmailAsync(string token);
        Task<bool> ResetPasswordAsync(string token, string newPassword);
        Task<User?> ForgotPasswordAsync(string email);
    }
}
