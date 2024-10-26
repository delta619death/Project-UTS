using OtpNet;
using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace SampleSecureWeb.Services
{
    public class OtpService
    {
        public string GenerateOtp()
        {
            var secretKey = Base32Encoding.ToBytes("JBSWY3DPEHPK3PXP");
            var totp = new Totp(secretKey, step: 300);
            return totp.ComputeTotp(DateTime.UtcNow);
        }

        public bool ValidateOtp(string inputOtp)
        {
            var secretKey = Base32Encoding.ToBytes("JBSWY3DPEHPK3PXP");
            var totp = new Totp(secretKey, step: 300);
            long timeStepMatched;
            return totp.VerifyTotp(inputOtp, out timeStepMatched, window: null);
        }

        // Update SendOtpEmailAsync to use your App Password
        public async Task SendOtpEmailAsync(string email, string otpCode)
        {
            // Gunakan App Password yang Anda dapatkan dari Google
            var smtpClient = new SmtpClient("smtp.gmail.com")
            {
                Port = 587, // Port untuk TLS
                Credentials = new NetworkCredential("michaeljonathan619@gmail.com", "wpxmjydzkwlzuabc"), // Ganti dengan email dan App Password Anda
                EnableSsl = true, // Pastikan SSL diaktifkan
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress("your-email@gmail.com"), // Email pengirim
                Subject = "Your OTP Code",
                Body = $"Your OTP code is {otpCode}", // Isi email yang akan dikirim
                IsBodyHtml = false,
            };

            mailMessage.To.Add(email); // Tambahkan penerima

            // Kirim email secara asynchronous
            await smtpClient.SendMailAsync(mailMessage);
        }
    }
}
