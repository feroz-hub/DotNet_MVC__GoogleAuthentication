using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SampleGoogleAuth.Data;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<ApplicationDbContext>();
builder.Services.AddControllersWithViews();
builder.Services.Configure<IdentityOptions>(option =>
{
    option.Password.RequireDigit = true;
    option.Password.RequiredLength = 8;
    option.Password.RequireLowercase = true;
    option.Password.RequireNonAlphanumeric = true;
    option.Password.RequireUppercase = true;
    option.Lockout.AllowedForNewUsers = true;
    option.Lockout.MaxFailedAccessAttempts = 5;
    option.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);

    option.User.RequireUniqueEmail = false;
});

builder.Services.ConfigureApplicationCookie(option =>
{
    option.Cookie.HttpOnly = true;
    option.ExpireTimeSpan = TimeSpan.FromMinutes(5);
    option.LoginPath = "/Identity/Account/Login";
    option.LogoutPath = "/Identity/Account/Logout";
    option.SlidingExpiration = true;
});

builder.Services.AddAuthentication().AddGoogle(option =>
{
    option.ClientId = builder.Configuration["Authentication:Google:ClientId"]!;
    option.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"]!;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
