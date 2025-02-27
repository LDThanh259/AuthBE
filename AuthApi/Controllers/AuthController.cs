using AuthApi.Data;
using AuthApi.DTOs;
using AuthApi.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthApi.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting.Server;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace AuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly ITokenService _tokenService;
        private readonly AuthDbContext _context;
        private readonly ILogger<AuthController> _logger;

        public AuthController(UserManager<User> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, IEmailService emailService, ITokenService tokenService, AuthDbContext context, ILogger<AuthController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
            _tokenService = tokenService;
            _context = context;
            _logger = logger;
        }

        [HttpPost]
        [Route("register")]
        public async Task<ApiResponse<object>> Register([FromBody] RegisterRequestDTO model)
        {
            try
            {
                if (await _userManager.FindByNameAsync(model.UserName) != null)
                    return ApiResponse<object>.ErrorResult("Tên đăng nhập đã tồn tại");

                if (await _userManager.FindByEmailAsync(model.Email) != null)
                    return ApiResponse<object>.ErrorResult("Email đã được đăng ký");

                User user = new User
                {
                    UserName = model.UserName,
                    Email = model.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (!result.Succeeded)
                    return ApiResponse<object>.ErrorResult("Lỗi đăng ký", result.Errors.Select(e => e.Description));

                await _userManager.AddToRoleAsync(user, RoleName.Client);
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action("ConfirmEmail", "Auth", new { userId = user.Id, token }, Request.Scheme)!;
                await _emailService.SendActivationEmailAsync(user.Email, confirmationLink);

                return ApiResponse<object>.SuccessResult(null, "Đăng ký thành công. Vui lòng kiểm tra email.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Lỗi đăng ký");
                return ApiResponse<object>.ErrorResult("Lỗi hệ thống");
            }

        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return BadRequest("Người dùng không tồn tại");

            var result = await _userManager.ConfirmEmailAsync(user, Uri.UnescapeDataString(token));
            if (!result.Succeeded) return BadRequest("Token không hợp lệ");

            return Redirect("http://localhost:3000/login?confirmed=true");
        }

        [HttpPost]
        [Route("login")]
        public async Task<ApiResponse<LoginResponseDTO>> Login([FromBody] LoginRequestDTO model)
        {
            var user = await _userManager.FindByNameAsync(model.Identifier)
                 ?? await _userManager.FindByEmailAsync(model.Identifier);

            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return ApiResponse<LoginResponseDTO>.ErrorResult("Thông tin đăng nhập không chính xác");

            if (!user.EmailConfirmed)
                return ApiResponse<LoginResponseDTO>.ErrorResult("Vui lòng xác thực email trước");

            // Generate tokens
            var tokens = await GenerateTokens(user);
            await _userManager.ResetAccessFailedCountAsync(user);

            return ApiResponse<LoginResponseDTO>.SuccessResult(tokens);
        }
        [Authorize]
        [HttpGet("validate")]
        public async Task<ApiResponse<UserResponseDTO>> ValidateToken()
        {
            try
            {
                var user = HttpContext.User;

                var userId = user.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
                var username = user.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
                var email = user.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
                var roles = user.Claims.Where(c => c.Type == ClaimTypes.Role)
                                       .Select(c => c.Value)
                                       .ToList();

                var userData = new UserResponseDTO
                {
                    Id = userId,
                    Username = username,
                    Email = email,
                    Roles = roles
                };

                return ApiResponse<UserResponseDTO>.SuccessResult
                (
                    userData
                );
            }
            catch (SecurityTokenException ex)
            {
                _logger.LogError(ex, "Invalid token");
                return ApiResponse<UserResponseDTO>.ErrorResult(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token validation error");
                return ApiResponse<UserResponseDTO>.ErrorResult("Internal server error");
            }
        }

        [HttpPost("google")]
        public async Task<ApiResponse<LoginResponseDTO>> GoogleLogin([FromBody] GoogleAuthRequest request)
        {
            try
            {
                const string provider = "Google";
                var payload = await ValidateGooogleToken(request.Token);
                var providerKey = payload.Subject;

                var user = await _userManager.FindByLoginAsync(provider, providerKey);
                if (user == null)
                {
                    user = await _userManager.FindByEmailAsync(payload.Email);
                    if (user == null)
                    {
                        var username = !string.IsNullOrEmpty(payload.Name)
                            ? payload.Name.Replace(" ", "_")
                            : payload.Email.Split('@')[0];

                        user = new User
                        {
                            UserName = username,
                            Email = payload.Email,
                            EmailConfirmed = true
                        };

                        var createResult = await _userManager.CreateAsync(user);

                        if (!createResult.Succeeded)
                        {
                            return ApiResponse<LoginResponseDTO>.ErrorResult(
                                "Registration Error",
                                errors: createResult.Errors
                                    .Select(e => $"{e.Code}: {e.Description}")
                                    .ToList()
                            );
                        }

                        if (!await _roleManager.RoleExistsAsync(RoleName.Client))
                        {
                            var createRoleResult = await _roleManager.CreateAsync(new IdentityRole(RoleName.Client));
                            if (!createRoleResult.Succeeded)
                            {
                                return ApiResponse<LoginResponseDTO>.ErrorResult(
                                    "Create role error",
                                    createRoleResult.Errors
                                    .Select(e => $"{e.Code}: {e.Description}")
                                    .ToList()
                                );
                            }
                        }

                        var addToRoleResult = await _userManager.AddToRoleAsync(user, RoleName.Client);
                        if (!addToRoleResult.Succeeded)
                        {
                            return ApiResponse<LoginResponseDTO>.ErrorResult(
                                "Add to role Error",
                                errors: addToRoleResult.Errors
                                    .Select(e => $"{e.Code}: {e.Description}")
                                    .ToList()
                            );
                        }
                    }

                    var userLoginInfo = new UserLoginInfo(provider, providerKey, "Google");
                    //lưu vào database bảng UserLogin
                    var addLoginResult = await _userManager.AddLoginAsync(user, userLoginInfo);
                    if (!addLoginResult.Succeeded)
                    {
                        return ApiResponse<LoginResponseDTO>.ErrorResult(
                            "Add login Error",
                            errors: addLoginResult.Errors
                                .Select(e => $"{e.Code}: {e.Description}")
                                .ToList()
                        );
                    }
                }

                var tokens = await GenerateTokens(user);
                return ApiResponse<LoginResponseDTO>.SuccessResult(tokens);
            }
            catch (InvalidJwtException ex)
            {
                return ApiResponse<LoginResponseDTO>.ErrorResult("Invalid Google token");
            }
            catch (Exception ex)
            {
                return ApiResponse<LoginResponseDTO>.ErrorResult("An error occurred during login");
            }
        }

        private async Task<GoogleJsonWebSignature.Payload> ValidateGooogleToken(string token)
        {
            var settings = new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new[] { _configuration["Authentication:Google:ClientId"] }
            };

            return await GoogleJsonWebSignature.ValidateAsync(token, settings);
        }

        [Authorize]
        [HttpGet("logout")]
        public async Task<ApiResponse<object>> Logout()
        {
            var userIdClaim = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
            if (userIdClaim == null)
            {
                return ApiResponse<object>.ErrorResult("Invalid access token.");
            }

            string userId = userIdClaim.Value;

            var storedRefreshToken = await _context.RefreshTokens
                .Include(rt => rt.User)
                .Where(rt => rt.UserId == userId && !rt.IsRevoked)
                .ToListAsync();

            foreach (var refreshToken in storedRefreshToken)
            {
                refreshToken.IsRevoked = true;
                refreshToken.RevokedAt = DateTime.Now;
            }

            await _context.SaveChangesAsync();

            return ApiResponse<object>.SuccessResult(null, "Logout successful. Refresh token has been revoked.");
        }

        [HttpPost("refresh-token")]
        public async Task<ApiResponse<LoginResponseDTO>> RefreshToken(RefreshTokenRequestDTO model)
        {
            try
            {
                // Validate input
                if (string.IsNullOrEmpty(model.RefreshToken))
                    return ApiResponse<LoginResponseDTO>.ErrorResult("Refresh token is required");

                // Hash and validate token
                var hashedToken = _tokenService.HashRefreshToken(model.RefreshToken);
                var storedToken = await _context.RefreshTokens
                    .Include(rt => rt.User)
                    .FirstOrDefaultAsync(rt =>
                        rt.Token == hashedToken &&
                        !rt.IsRevoked &&
                        rt.ExpiresAt > DateTime.UtcNow);

                // Token validation
                if (storedToken == null)
                    return ApiResponse<LoginResponseDTO>.ErrorResult("Invalid or expired refresh token");

                if (storedToken.User == null)
                    return ApiResponse<LoginResponseDTO>.ErrorResult("User not found");

                // Revoke current refresh token
                storedToken.IsRevoked = true;
                storedToken.RevokedAt = DateTime.UtcNow;
                _context.RefreshTokens.Update(storedToken);

                // Generate new tokens
                var newTokens = await GenerateTokens(storedToken.User);

                // Persist changes
                await _context.SaveChangesAsync();

                return ApiResponse<LoginResponseDTO>.SuccessResult(newTokens, "Token refreshed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Refresh token error");
                return ApiResponse<LoginResponseDTO>.ErrorResult("Internal server error");
            }
        }


        private async Task<LoginResponseDTO> GenerateTokens(User user)
        {
            var claims = new List<Claim>
            {
                new(ClaimTypes.Name, user.UserName),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(ClaimTypes.Email, user.Email),
                new(ClaimTypes.NameIdentifier, user.Id)
            };
            claims.AddRange((await _userManager.GetRolesAsync(user)).Select(r => new Claim(ClaimTypes.Role, r)));

            // Revoke old tokens
            await RevokeOldRefreshTokens(user.Id);

            // Token generation
            var accessToken = _tokenService.GenerateAccessToken(claims);
            var refreshToken = _tokenService.GenerateRefreshToken();

            await SaveRefreshToken(user.Id, refreshToken);

            return new LoginResponseDTO
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
            };
        }

        private async Task RevokeOldRefreshTokens(string userId)
        {
            var oldTokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == userId && !rt.IsRevoked)
                .ToListAsync();

            foreach (var token in oldTokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.Now;
            }

            await _context.SaveChangesAsync();
        }

        private async Task SaveRefreshToken(string userId, string refreshToken)
        {
            _context.RefreshTokens.Add(new RefreshToken
            {
                Token = _tokenService.HashRefreshToken(refreshToken),
                UserId = userId,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                CreatedAt = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();
        }

    }
}
