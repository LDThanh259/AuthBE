using AuthApi.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        [Authorize(Roles = RoleName.Admin)]
        [HttpGet("admin")]
        public IActionResult AdminEndpoint()
        {
            return Ok("This is an admin endpoint");
        }
    }
}
