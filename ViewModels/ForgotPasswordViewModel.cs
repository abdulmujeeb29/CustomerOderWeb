using System.ComponentModel.DataAnnotations;

namespace CustomerOrderWeb.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }   
    }
}
