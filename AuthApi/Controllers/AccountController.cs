using AuthApi.DTOs;
using AuthApi.Models;
using AuthApi.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Security.Claims;

namespace AuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly IEmailService _emailService;
        public AccountController(UserManager<User> userManager, IEmailService emailService)
        {
            _userManager = userManager;
            _emailService = emailService;
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequestDTO model)
        {
            var userExists = await _userManager.FindByEmailAsync(model.Email);
            if(userExists == null)
            {
                return Ok("If your email is registered, you will receive a password reset link.");
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(userExists);
            var encodedToken = Uri.EscapeDataString(token);

            var resetLink = $"http://localhost:3000/api/Account/reset-password?email={userExists.Email}&token={encodedToken}";
            await _emailService.SendPasswordResetEmailAsync(userExists.Email, resetLink);
            return Ok("Password reset link has been sent to your email.");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequestDTO model)
        {
            var userExists = await _userManager.FindByEmailAsync(model.Email);
            if (userExists == null)
            {
                return NotFound("User not found");
            }
            var decodedToken = Uri.UnescapeDataString(model.Token);
            var result = await _userManager.ResetPasswordAsync(userExists, decodedToken, model.NewPassword);
            if(!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok("Password reset successfully");
        }

        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequestDTO model)
        {
            var identityName = User.Identity?.Name;
            var nameClaim = User.FindFirst(ClaimTypes.Name)?.Value;
            var userExists = await _userManager.GetUserAsync(User);
            if (userExists == null)
            {
                return Unauthorized("User not found");
            }

            var result = await _userManager.ChangePasswordAsync(userExists, model.CurrentPassword, model.NewPassword);
            if(!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok("Password changed successfully");
        }
    }
}
