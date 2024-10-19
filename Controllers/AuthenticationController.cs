using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Text;
using CustomerOrderWeb.ViewModels;
using static CustomerOrderWeb.Controllers.AuthenticationController;
using System.Text.Json.Serialization;

namespace CustomerOrderWeb.Controllers
{
    public class AuthenticationController : Controller
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiBaseUrl;
        public AuthenticationController(IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            _httpClient = httpClientFactory.CreateClient();
            _apiBaseUrl = configuration["ApiSettings:BaseUrl"];
        }
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(UserViewModel user)
        {

            var jsonContent = new StringContent(JsonSerializer.Serialize(user), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync($"{_apiBaseUrl}/api/Auth/register", jsonContent);

            if (response.IsSuccessStatusCode)
            {
                TempData["SuccessMessage"] = "Registeration successful, You can now log in";
                return RedirectToAction("Login");
            }
            ModelState.AddModelError(string.Empty, "Registration failed. Please try again.");
            return View(user);

        }
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(UserViewModel user)
        {
            var jsonContent = new StringContent(JsonSerializer.Serialize(user), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync($"{_apiBaseUrl}/api/Auth/login", jsonContent);

            if (response.IsSuccessStatusCode)
            {
                // Extract the token from the response
                var jsonResponse = await response.Content.ReadAsStringAsync();
                Console.WriteLine(jsonResponse);
                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(jsonResponse);  // assuming token is returned as a dict

                if (tokenResponse != null && !string.IsNullOrEmpty(tokenResponse.Token))
                {
                    // Store token in session or cookie
                    HttpContext.Session.SetString("JWTToken", tokenResponse.Token); // Store in session

                    TempData["SuccessMessage"] = "Login Succesful";
                    return RedirectToAction("ProtectedPage");
                }

                // Store token in session or cookie
                
            }
            ModelState.AddModelError(string.Empty, "Invalid login attempt. Please check your credentials and try again.");
            return View(user);


        }
        public class TokenResponse
        {
            [JsonPropertyName("token")]
            public string Token { get; set; }
        }

        public IActionResult Logout()
        {
            return RedirectToAction("Index");
        }

        [HttpPost]
        public async Task<IActionResult> LogoutApi()
        {
            var response = await _httpClient.PostAsync($"{_apiBaseUrl}/api/Auth/logout", null);

            if (response.IsSuccessStatusCode)
            {
                // Clear JWT from session or cookie here
                return RedirectToAction("Index");
            }

            // Handle logout failure
            return RedirectToAction("Index");
        }
        public IActionResult ProtectedPage()
        {
            return View();
        }

    }
}
