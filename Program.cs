using CustomerOrderWeb.Helpers;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme; // Set DefaultSignInScheme
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.LoginPath = "/Authentication/Login";  // Specify your login route here
    options.ExpireTimeSpan = TimeSpan.FromMinutes(5);   
    //options.AccessDeniedPath = "/Account/AccessDenied";
})
.AddGoogle(options =>
{
    options.ClientId = "7958666719-dgjo8p6hikja1afv4u0u1fn38i5ojqe4.apps.googleusercontent.com";
    options.ClientSecret = "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";
    options.CallbackPath = "/signin-google"; // Google will redirect here after successful login
});



builder.Services.AddHttpClient();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(5); // Set session timeout
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Add authentication services
builder.Services.AddTransient<JwtTokenHandler>();
builder.Services.AddHttpClient("ApiWithJwt").AddHttpMessageHandler<JwtTokenHandler>();
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddScoped<ApiHelper>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
