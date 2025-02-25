namespace AuthApi.DTOs
{
    public class LoginResponseDTO
    {
        public string AccessToken { set; get; }
        public string RefreshToken { set; get; }
    }
}
