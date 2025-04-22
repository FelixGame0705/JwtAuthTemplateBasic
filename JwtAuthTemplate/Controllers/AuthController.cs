using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JwtAuthTemplate.Entities;
using JwtAuthTemplate.Models;
using JwtAuthTemplate.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuthTemplate.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        public static User user = new();

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            var user = await authService.RegisterAsync(request);

            if (user is null)
            {
                return BadRequest("User already exists.");
            }
            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDto>> Login(UserDto request)
        {
            var token = await authService.LoginAsync(request);
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
        public async Task<ActionResult<User>> RefreshToken(RefreshTokenRequestDto request)
        {
            var user = await authService.RefreshTokenAsync(request);
            if (user is null)
            {
                return BadRequest("Invalid token.");
            }
            return Ok(user);
        }
    }
}
