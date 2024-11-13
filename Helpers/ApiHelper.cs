using System.Text.Json;
using System.Text;
using System.Net.Http.Headers;

namespace CustomerOrderWeb.Helpers
{
    public class ApiHelper
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiBaseUrl;
        public ApiHelper(IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            _httpClient = httpClientFactory.CreateClient();
            _apiBaseUrl = configuration["ApiSettings:BaseUrl"];
        }

        public async Task<HttpResponseMessage> RegisterUserAsync(object user)
        {
            var jsonContent = new StringContent(JsonSerializer.Serialize(user), Encoding.UTF8, "application/json");
            return await _httpClient.PostAsync($"{_apiBaseUrl}/api/Auth/register", jsonContent);
        }

        public async Task<HttpResponseMessage> LoginUserAsync(object user)
        {
            var jsonContent = new StringContent(JsonSerializer.Serialize(user), Encoding.UTF8, "application/json");
            return await _httpClient.PostAsync($"{_apiBaseUrl}/api/Auth/login", jsonContent);
        }

        public async Task<HttpResponseMessage> ForgotPasswordAsync(string email)
        {
            var jsonContent = new StringContent(JsonSerializer.Serialize(email), Encoding.UTF8, "application/json");
            return await _httpClient.PostAsync($"{_apiBaseUrl}/api/Auth/forgot-password", jsonContent);
        }

        // Reset Password
        public async Task<HttpResponseMessage> ResetPasswordAsync(string newPassword, string token)
        {
            var jsonContent = new StringContent(JsonSerializer.Serialize(newPassword), Encoding.UTF8, "application/json");
            return await _httpClient.PostAsync($"{_apiBaseUrl}/api/Auth/reset-password?token={token}", jsonContent);
        }

        // Change Password
        public async Task<HttpResponseMessage> ChangePasswordAsync(string newPassword, string token)
        {
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var jsonContent = new StringContent(JsonSerializer.Serialize(newPassword), Encoding.UTF8, "application/json");
            return await _httpClient.PostAsync($"{_apiBaseUrl}/api/Auth/change-password", jsonContent);
        }

        // Google User Check
        public async Task<HttpResponseMessage> CheckGoogleUserAsync(string email)
        {
            var requestData = new { Email = email };
            var jsonContent = new StringContent(JsonSerializer.Serialize(requestData), Encoding.UTF8, "application/json");
            return await _httpClient.PostAsync($"{_apiBaseUrl}/api/Auth/check-user", jsonContent);
        }
    }
}
