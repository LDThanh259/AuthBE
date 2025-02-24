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
        public async Task<IActionResult> Register([FromBody] RegisterRequestDTO model)
        {
            var userExists = await _userManager.FindByNameAsync(model.UserName);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new { Status = "Error", Message = "User already exists!" });

            userExists = await _userManager.FindByEmailAsync(model.Email);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new { Status = "Error", Message = "User already exists!" });

            User newUser = new User
            {
                UserName = model.UserName,
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            var result = await _userManager.CreateAsync(newUser, model.Password);
            if(!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            if (!await _roleManager.RoleExistsAsync(RoleName.Client))
            {
                await _roleManager.CreateAsync(new IdentityRole("Client"));
            }

            await _userManager.AddToRoleAsync(newUser, RoleName.Client);

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
            var confirmationLink = $"https://localhost:7217/api/Auth/confirm-email?userId={newUser.Id}&token={Uri.EscapeDataString(token)}";

            await _emailService.SendActivationEmailAsync(newUser.Email, confirmationLink);

            return Ok("User registered! Please check your email to confirm.");
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var userExixts = await _userManager.FindByIdAsync(userId);
            if(userExixts == null)
            {
                return BadRequest("Invalid user");
            }

            var decodedToken = Uri.UnescapeDataString(token);
            var result = await _userManager.ConfirmEmailAsync(userExixts, decodedToken);
            if (result.Succeeded) return Redirect("http://localhost:3000/login");

            return BadRequest("Invalid token or email already confirmed.");
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDTO model, [FromQuery] string returnUrl = "/")
        {
            if (!IsValidReturnUrl(returnUrl))
            {
                return Redirect($"http://localhost:3000/login?error=Invalid return URL");
            }

            var userExists = await _userManager.FindByNameAsync(model.Identified)
                            ?? await _userManager.FindByEmailAsync(model.Identified);

            if (userExists == null)
            {
                return Unauthorized("Invalid credentials");
            }

            if (await _userManager.IsLockedOutAsync(userExists))
            {
                return BadRequest("Tài khoản đã bị khóa. Vui lòng thử lại sau.");
            }

            if (!await _userManager.CheckPasswordAsync(userExists, model.Password))
            {
                await _userManager.AccessFailedAsync(userExists);
                return Unauthorized("Invalid credentials");
            }

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, userExists.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Email, userExists.Email),
                new Claim(ClaimTypes.NameIdentifier, userExists.Id),
            };

            var userRoles = await _userManager.GetRolesAsync(userExists);
            authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

            var oldTokens = _context.RefreshTokens.Where(rt => rt.UserId == userExists.Id && !rt.IsRevoked);
            _context.RefreshTokens.RemoveRange(oldTokens);

            var accessToken = CreateAccessToken(authClaims);
            var refreshToken = CreateRefreshToken();

            var refreshTokenEntity = new RefreshToken
            {
                Token = HashToken(refreshToken),
                UserId = userExists.Id,
                //Refresh tokens are set to expire after 7 days (you can adjust this as needed).
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                CreatedAt = DateTime.UtcNow,
                IsRevoked = false
            };
            // The hashed refresh token, along with associated user and client information, is stored in the RefreshTokens table.
            _context.RefreshTokens.Add(refreshTokenEntity);
            await _context.SaveChangesAsync();

            await _userManager.UpdateAsync(userExists);
            await _userManager.ResetAccessFailedCountAsync(userExists);

            //Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            //{
            //    HttpOnly = true,
            //    Secure = false,
            //    SameSite = SameSiteMode.Lax,
            //    Expires = DateTime.Now.AddDays(7)
            //});

            return Ok(new
            {
                accessToken,
                refreshToken,
                redirectUrl = returnUrl
            });
        }


        [HttpGet("external-login")]
        public IActionResult ExternalLogin([FromQuery] string returnUrl = "/")
        {
            if (!IsValidReturnUrl(returnUrl))
            {
                return Redirect($"http://localhost:3000/login?error=Invalid return URL");
            }

            var redirectUrl = Url.Action("ExternalLoginCallback", "Auth", new { returnUrl }, protocol: Request.Scheme);
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("external-login-callback")]
        public async Task<IActionResult> ExternalLoginCallback([FromQuery] string returnUrl = "/")
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);
            if(!authenticateResult.Succeeded)
            {
                return Redirect($"http://localhost:3000/login?error=Google authentication failed&returnUrl={returnUrl}");
            }

            //var claims = authenticateResult.Principal.Claims.Select(c => new { c.Type, c.Value });
            //{
            //    "claims": [
            //                      {
            //                        "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
            //          "value": "104275176068529044714"
            //                      },
            //        {
            //                        "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
            //          "value": "Thanh LD"
            //        },
            //        {
            //                        "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
            //          "value": "Thanh"
            //        },
            //        {
            //                        "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
            //          "value": "LD"
            //        },
            //        {
            //                        "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            //          "value": "thanhldchatgpt@gmail.com"
            //        }
            //      ]
            //    }

            var email = authenticateResult.Principal.FindFirst(ClaimTypes.Email)?.Value;
            var name = authenticateResult.Principal.FindFirst(ClaimTypes.Name)?.Value;
            var providerKey = authenticateResult.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var provider = GoogleDefaults.AuthenticationScheme;

            if(string.IsNullOrEmpty(email) || string.IsNullOrEmpty(name))
            {
                return Redirect($"http://localhost:3000/login?error=Google authentication failed&returnUrl={returnUrl}");
            }

            // tìm kiếm trên bảng UserLogin xem có người dùng nào với provider, providerKey
            var user = await _userManager.FindByLoginAsync(provider, providerKey);
            if(user == null)
            {
                user = await _userManager.FindByEmailAsync(email);
                if(user == null)
                {
                    var sanitizedUsername = name.Replace(" ", "_");
                    user = new User
                    {
                        UserName = sanitizedUsername,
                        Email = email,
                        EmailConfirmed = true
                    };

                    var createResult = await _userManager.CreateAsync(user);

                    if(!createResult.Succeeded)
                    {
                        return Redirect($"http://localhost:3000/login?error={createResult.Errors}&returnUrl={returnUrl}");
                    }

                    if (!await _roleManager.RoleExistsAsync(RoleName.Client))
                    {
                        var createRoleResult = await _roleManager.CreateAsync(new IdentityRole(RoleName.Client));
                        if (!createRoleResult.Succeeded)
                        {
                            return BadRequest(createResult.Errors);
                        }

                    }
                    var addToRoleResult = await _userManager.AddToRoleAsync(user, RoleName.Client);
                    if (!addToRoleResult.Succeeded)
                    {
                        return BadRequest(createResult.Errors);
                    }
                }

                var userLoginInfo = new UserLoginInfo(provider, providerKey, "Google");
                //lưu vào database bảng UserLogin
                var addLoginResult = await _userManager.AddLoginAsync(user, userLoginInfo);
                if (!addLoginResult.Succeeded)
                {
                    return BadRequest(addLoginResult.Errors);
                }
            }

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
            };
            var userRoles = await _userManager.GetRolesAsync(user);
            authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

            var accessToken = CreateAccessToken(authClaims);
            var refreshToken = CreateRefreshToken();

            var oldTokens = _context.RefreshTokens.Where(rt => rt.UserId == user.Id && !rt.IsRevoked);
            _context.RefreshTokens.RemoveRange(oldTokens);

            var refreshTokenEntity = new RefreshToken
            {
                Token = HashToken(refreshToken),
                UserId = user.Id,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                CreatedAt = DateTime.UtcNow,
                IsRevoked = false
            };
            _context.RefreshTokens.Add(refreshTokenEntity);
            await _context.SaveChangesAsync();

            //Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            //{
            //    HttpOnly = true,
            //    Secure = false,
            //    SameSite = SameSiteMode.Lax,
            //    Expires = DateTime.UtcNow.AddDays(7)
            //});

            var redirectUrlWithToken = $"http://localhost:3000{returnUrl}";
            return Redirect(redirectUrlWithToken);
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDTO model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var hashedToken = HashToken(model.RefreshToken);

            var storedRefreshToken = await _context.RefreshTokens
                .Include(rf => rf.User)
                .FirstOrDefaultAsync(rf => rf.Token == hashedToken);

            if (storedRefreshToken == null)
            {
                return Unauthorized("Invalid refresh token.");
            }
            if (storedRefreshToken.IsRevoked)
            {
                return Unauthorized("Refresh token has been revoked.");
            }
            if (storedRefreshToken.ExpiresAt < DateTime.UtcNow)
            {
                return Unauthorized("Refresh token has expired.");
            }

            var user = storedRefreshToken.User;

            storedRefreshToken.IsRevoked = true;
            storedRefreshToken.RevokedAt = DateTime.UtcNow;

            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                };
            var userRoles = await _userManager.GetRolesAsync(user);
            authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

            var accessToken = CreateAccessToken(authClaims);
            var refreshToken = CreateRefreshToken();

            var hashedNewRefreshToken = HashToken(refreshToken);
            var newRefreshTokenEntity = new RefreshToken
            {
                Token = hashedNewRefreshToken,
                UserId = user.Id,
                ExpiresAt = DateTime.UtcNow.AddDays(7), // Adjust as needed
                CreatedAt = DateTime.UtcNow,
                IsRevoked = false
            };
            // Store the new refresh token
            _context.RefreshTokens.Add(newRefreshTokenEntity);

            //Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            //{
            //    HttpOnly = true,
            //    Secure = false,
            //    SameSite = SameSiteMode.Lax,
            //    Expires = DateTime.Now.AddDays(7)
            //});

            return Ok(new
            {
                accessToken,
                refreshToken,
            });
        }

        private string CreateRefreshToken()
        {
            var random = new byte[32];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(random);

                return Convert.ToBase64String(random);
            }
        }

        private string CreateAccessToken(List<Claim> authClaims)
        {
            var authSingningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(_configuration.GetValue<double>("JWT:TokenValidityInMinutes")),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSingningKey, SecurityAlgorithms.HmacSha256)
             );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(hashedBytes);

            //var salt = new byte[16];
            //RandomNumberGenerator.Fill(salt);
            //using var sha256 = SHA256.Create();
            //var combinedBytes = Encoding.UTF8.GetBytes(token).Concat(salt).ToArray();
            //return Convert.ToBase64String(sha256.ComputeHash(combinedBytes)) + ":" + Convert.ToBase64String(salt);
        }

        private bool IsValidReturnUrl(string returnUrl)
        {
            var allowedHosts = new List<string> { "localhost:3000", "yourdomain.com" };
            if (Uri.TryCreate(returnUrl, UriKind.Absolute, out Uri uri))
            {
                return allowedHosts.Contains(uri.Host);
            }
            return returnUrl.StartsWith("/");
        }

    }
}
