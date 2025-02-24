using AuthApi.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = RoleName.Client)]
    public class ClientController : ControllerBase
    {
        [HttpGet("user-only")]
        public IActionResult UserOnly()
        {
            return Ok("You are a User");
        }

        [HttpGet("profile")]
        public IActionResult Profile()
        {
            var user = HttpContext.User;

            if(user.Identity == null || !user.Identity.IsAuthenticated)
            {
                return Unauthorized(new { message = "User is not authenticated" });
            }
            var profile = new
            {
                UserId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value,
                Email = user.FindFirst(ClaimTypes.Email)?.Value,
                Name = user.FindFirst(ClaimTypes.Name)?.Value,
                Roles = user.FindFirst(ClaimTypes.Role)?.Value,
            };
            return Ok(profile);
        }
    }
}
