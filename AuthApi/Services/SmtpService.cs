using AuthApi.Models;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace AuthApi.Services
{
    public interface IEmailService
    {
        Task<bool> SendActivationEmailAsync(string recipientEmail, string actionLink);
        Task<bool> SendPasswordResetEmailAsync(string recipientEmail, string resetLink);

    }

    public class SmtpEmailService : IEmailService
    {
        private readonly IOptions<SMTP> _options;
        private readonly ILogger<SmtpEmailService> _logger;
        public SmtpEmailService(IOptions<SMTP> options, ILogger<SmtpEmailService> logger)
        {
            _options = options;
            _logger = logger;
        }

        public async Task<bool> SendActivationEmailAsync(string recipientEmail, string actionLink)
        {
            try
            {
                // Tạo đối tượng MimeMessage
                var emailMessage = new MimeMessage();

                // Thiết lập thông tin người gửi và người nhận
                emailMessage.From.Add(new MailboxAddress(_options.Value.DisplayName, _options.Value.UserName));
                emailMessage.To.Add(new MailboxAddress("", recipientEmail));

                // Thiết lập tiêu đề email
                emailMessage.Subject = "Activate Your Account";

                // Xây dựng nội dung email với định dạng text và HTML
                var bodyBuilder = new BodyBuilder
                {
                    TextBody = $"Please activate your account by clicking here: {actionLink}",
                    HtmlBody = $"<strong>Please activate your account:</strong> <a href='{actionLink}'>{actionLink}</a>"
                };
                emailMessage.Body = bodyBuilder.ToMessageBody();

                // Sử dụng MailKit SmtpClient để gửi email
                using (var smtp = new MailKit.Net.Smtp.SmtpClient())
                {
                    // Kết nối đến SMTP server với cấu hình từ _options
                    await smtp.ConnectAsync(_options.Value.Host, _options.Value.Port, SecureSocketOptions.StartTls);

                    // Nếu SMTP server yêu cầu xác thực, tiến hành xác thực
                    if (!string.IsNullOrWhiteSpace(_options.Value.UserName))
                    {
                        await smtp.AuthenticateAsync(_options.Value.UserName, _options.Value.Password);
                    }

                    // Gửi email
                    await smtp.SendAsync(emailMessage);

                    // Ngắt kết nối và giải phóng tài nguyên
                    await smtp.DisconnectAsync(true);
                }

                return true;
            }
            catch (Exception ex)
            {
                // Ở đây bạn có thể ghi log exception hoặc xử lý lỗi tùy theo nhu cầu
                _logger.LogError($"Error sending email: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> SendPasswordResetEmailAsync(string recipientEmail, string resetLink)
        {
            try
            {
                var emailMessage = new MimeMessage();
                emailMessage.From.Add(new MailboxAddress(_options.Value.DisplayName, _options.Value.UserName));
                emailMessage.To.Add(new MailboxAddress("", recipientEmail));
                emailMessage.Subject = "Reset Your Password";

                var bodyBuilder = new BodyBuilder
                {
                    TextBody = $"You can reset your password by clicking the link: {resetLink}",
                    HtmlBody = $"<strong>Reset your password:</strong> <a href='{resetLink}'>Click here</a>"
                };
                emailMessage.Body = bodyBuilder.ToMessageBody();

                using (var smtp = new MailKit.Net.Smtp.SmtpClient())
                {
                    await smtp.ConnectAsync(_options.Value.Host, _options.Value.Port, SecureSocketOptions.StartTls);
                    if (!string.IsNullOrWhiteSpace(_options.Value.UserName))
                    {
                        await smtp.AuthenticateAsync(_options.Value.UserName, _options.Value.Password);
                    }
                    await smtp.SendAsync(emailMessage);
                    await smtp.DisconnectAsync(true);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error sending password reset email: {ex.Message}");
                return false;
            }
        }
    }
}
