namespace JwtAuthTemplate.Entities
{
    public class User
    {
        public Guid Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Role { get; set; } = "User";
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
        public string? VerificationToken { get; set; } // Token xác thực email
        public bool IsEmailVerified { get; set; } = false; // Trạng thái xác thực email
    }
}
