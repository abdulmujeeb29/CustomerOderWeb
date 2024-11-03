using System.ComponentModel.DataAnnotations;

namespace CustomerOrderWeb.ViewModels
{
    public class ResetPasswordViewModel
    {
        [Required]
        public string Token { get; set; }

        [Required]
        
        public string NewPassword { get; set; }

        [Required]
        
        public string ConfirmPassword { get; set; }
    }
}
