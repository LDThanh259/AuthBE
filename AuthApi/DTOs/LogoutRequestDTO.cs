using System.ComponentModel.DataAnnotations;

namespace AuthApi.DTOs
{
    public class LogoutRequestDTO
    {
        [Required]
        public string RefreshToken { get; set; }
    }
}
