using System.ComponentModel.DataAnnotations;

namespace CustomerOrderWeb.ViewModels
{
    public class ChangePasswordViewModel
    {
        [Required(ErrorMessage = "Current Password is required.")]
        public string CurrentPassword { get; set; }
        [Required(ErrorMessage = " New Password is required.")]
        public string NewPassword { get; set; }
        [Required(ErrorMessage = "Confirm Password is required.")]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }
}
