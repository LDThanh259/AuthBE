using AuthApi.DTOs;
using AuthApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin")]
    public class RoleController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleController(UserManager<User> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        [HttpPost("create-role")]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequestDTO model)
        {
            if (await _roleManager.RoleExistsAsync(model.Role))
                return BadRequest("Role already exists");

            await _roleManager.CreateAsync(new IdentityRole(model.Role));
            return Ok($"Role {model.Role} created successfully");
        }

        [HttpPost]
        [Route("assign-role")]
        public async Task<IActionResult> AssignRole([FromBody] AssignRoleRequestDTO model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if(User == null)
            {
                return NotFound("User not found");
            }

            if(!await _roleManager.RoleExistsAsync(model.Role))
            {
                return BadRequest("Role does not exist");
            }

            await _userManager.AddToRoleAsync(userExists, model.Role);

            return Ok($"Role {model.Role} assigned to {model.Username}");
        }
    }
}
