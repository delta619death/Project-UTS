using System;
using System.ComponentModel.DataAnnotations;

namespace SampleSecureWeb.Models
{
    public class User
    {
        [Key]
        public string Username { get; set; } = null!;
        
        [Required]
        public string Password { get; set; } = null!;
        
        [Required]
        [EmailAddress]
        public string Email { get; set; } = null!;
        
        public string RoleName { get; set; } = null!;
        public bool IsActive { get; set; } = false;
    }
}
