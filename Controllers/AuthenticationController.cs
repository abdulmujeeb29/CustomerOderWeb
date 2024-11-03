﻿using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Text;
using CustomerOrderWeb.ViewModels;
using static CustomerOrderWeb.Controllers.AuthenticationController;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authorization;
using System.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using CustomerOrderApi.Models;

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
                    // Decode token claims
                    var handler = new JwtSecurityTokenHandler();
                    var jwtToken = handler.ReadJwtToken(tokenResponse.Token);
                    var claims = jwtToken.Claims.ToList();
                    claims.Add(new Claim(ClaimTypes.Name, user.Email));

                    // Create ClaimsIdentity and authenticate the user
                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

                    // Store token in session or cookie
                    HttpContext.Session.SetString("JWTToken", tokenResponse.Token); // Store in session

                    // Set the Authorization header for future requests
                    _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse.Token);

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

        public async Task<IActionResult> Logout()
        {
            // Clear the session and redirect to home page
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.Session.Remove("JWTToken");
            _httpClient.DefaultRequestHeaders.Authorization = null;
            return RedirectToAction("Index", "Home");
        }

        //[HttpPost]
        //public async Task<IActionResult> LogoutApi()
        //{
        //    var response = await _httpClient.PostAsync($"{_apiBaseUrl}/api/Auth/logout", null);

        //    if (response.IsSuccessStatusCode)
        //    {
        //        // Clear JWT from session and the HttpClient authorization header
        //        HttpContext.Session.Remove("JWTToken");
        //        _httpClient.DefaultRequestHeaders.Authorization = null; // Clear the header
        //        // Clear JWT from session or cookie here
        //        return RedirectToAction("Index");
        //    }

        //    // Handle logout failure
        //    return RedirectToAction("Index");
        //}

        [Authorize]
        public IActionResult ProtectedPage()
        {

            return View();
        }

        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                TempData["ErrorMessage"] = " please provide a valid Email";
                return View(model);
            }

            var jsonContent = new StringContent(JsonSerializer.Serialize(model.Email), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync($"{_apiBaseUrl}/api/Auth/forgot-password", jsonContent);

            if (response.IsSuccessStatusCode)
            {
                TempData["SucessMessage"] = "Kindly Check your mail , a reset link has been sent";
                return View(model);
            }
            TempData["ErrorMessage"] = "Failed to sent reset link, an error occured";
            return View(model);
        }
        [HttpGet]
        public IActionResult ResetPassword([FromQuery] string token)
        {
            var model = new ResetPasswordViewModel
            {
                Token = token // Pass the token to the view model
            };
            return View(model);
        }
        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                //var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage);
                TempData["ErrorMessage"] = "An error occured";
                return View(model);
            }

            if (model.NewPassword != model.ConfirmPassword)
            {
                TempData["ErrorMessage"] = "Passwords do not match.";
                return View(model);
            }

            // Create JSON content with the new password only, as the API expects
            var jsonContent = new StringContent(JsonSerializer.Serialize(model.NewPassword), Encoding.UTF8, "application/json");

            // Send token as query parameter macthing the api  requirements 
            var response = await _httpClient.PostAsync($"{_apiBaseUrl}/api/Auth/reset-password?token={model.Token}", jsonContent);

            if (response.IsSuccessStatusCode)
            {
                TempData["SuccessMessage"] = "Your password has been reset successfully. Please log in with your new password.";
                return RedirectToAction("Login", "Authentication");
            }

            TempData["ErrorMessage"] = "Failed to reset password. The token may be invalid or expired.";
            return View(model);
        }

    }
}
