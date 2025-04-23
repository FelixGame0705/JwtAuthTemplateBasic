using JwtAuthTemplate.Entities;
using JwtAuthTemplate.MailUtils;
using JwtAuthTemplate.Models;
using JwtAuthTemplate.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthTemplate.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ISendMailService _sendMailService;

        public AuthController(IAuthService authService, ISendMailService sendMailService)
        {
            _authService = authService;
            _sendMailService = sendMailService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            var user = await _authService.RegisterAsync(request);

            if (user is null)
            {
                return BadRequest("User already exists.");
            }

            // Tạo đường link xác thực
            var verificationLink = Url.Action(
                "VerifyEmail",
                "Auth",
                new { token = user.VerificationToken },
                Request.Scheme
            );

            // Gửi email xác thực
            var mailContent = new MailContent
            {
                To = user.Email,
                Subject = "Email Verification",
                Body =
                    $"<p>Click the link below to verify your email:</p><a href='{verificationLink}'>Verify Email</a>",
            };

            try
            {
                await _sendMailService.SendMail(mailContent);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Failed to send email: {ex.Message}");
            }

            return Ok("Registration successful. Please check your email to verify your account.");
        }

        [HttpGet("verify-email")]
        public async Task<IActionResult> VerifyEmail(string token)
        {
            var result = await _authService.VerifyEmailAsync(token);
            if (!result)
            {
                return BadRequest("Invalid or expired verification token.");
            }

            return Ok("Email verified successfully.");
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto request)
        {
            var user = await _authService.ForgotPasswordAsync(request.Email);
            if (user is null)
            {
                return BadRequest("Email not found.");
            }

            // Tạo đường link đặt lại mật khẩu
            var resetLink = Url.Action(
                "ResetPassword",
                "Auth",
                new { token = user.ResetPasswordToken },
                Request.Scheme
            );

            // Gửi email đặt lại mật khẩu
            var mailContent = new MailContent
            {
                To = request.Email,
                Subject = "Reset Your Password",
                Body =
                    $"<p>Click the link below to reset your password:</p><a href='{resetLink}'>Reset Password</a>",
            };

            try
            {
                await _sendMailService.SendMail(mailContent);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Failed to send email: {ex.Message}");
            }

            return Ok("Password reset link has been sent to your email.");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto request)
        {
            var result = await _authService.ResetPasswordAsync(request.Token, request.NewPassword);
            if (!result)
            {
                return BadRequest("Invalid or expired token.");
            }

            return Ok("Password has been reset successfully.");
        }

        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDto>> Login(UserDto request)
        {
            var token = await _authService.LoginAsync(request);
            if (token is null)
            {
                return BadRequest("Invalid username or password.");
            }
            return Ok(token);
        }

        [Authorize]
        [HttpGet]
        public ActionResult<string> AuthenticatedOnlyEndpoint()
        {
            return Ok("You are authenticated!");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public ActionResult<string> AdminOnlyEndpoint()
        {
            return Ok("You are admin!");
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDto>> RefreshToken(
            RefreshTokenRequestDto request
        )
        {
            var tokenResponse = await _authService.RefreshTokenAsync(request);
            if (tokenResponse is null)
            {
                return BadRequest("Invalid token.");
            }
            return Ok(tokenResponse);
        }
    }
}
