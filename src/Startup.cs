using CiamOptimizelyPortal.Extensions;
using EPiServer.Cms.UI.AspNetIdentity;
using EPiServer.Data;
using EPiServer.DependencyInjection;
using EPiServer.Scheduler;
using EPiServer.Web.Routing;
using CiamOptimizelyPortal.Services;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace CiamOptimizelyPortal;

public class Startup(IWebHostEnvironment webHostingEnvironment)
{
    public void ConfigureServices(IServiceCollection services)
    {
        if (webHostingEnvironment.IsDevelopment())
        {
            AppDomain.CurrentDomain.SetData("DataDirectory", Path.Combine(webHostingEnvironment.ContentRootPath, "App_Data"));

            services.Configure<SchedulerOptions>(options => options.Enabled = false);
        }

        services.Configure<DataAccessOptions>(o => o.UpdateDatabaseCompatibilityLevel = true);

        services
            .AddCmsAspNetIdentity<ApplicationUser>()
            .AddCms()
            .AddAlloy()
            .AddAdminUserRegistration()
            .AddEmbeddedLocalization<Startup>();

        services.AddDistributedMemoryCache();

        services.AddSingleton<ITokenValidationService, TokenValidationService>();

        // Required by Wangkanai.Detection
        // MVC controllers and Razor views for the CIAM portal
        services.AddControllersWithViews();
        services.AddHttpClient<NativeAuthService>();
        services.AddHttpClient<MfaService>();
        services.AddHttpClient<PasswordResetService>();
        services.AddDetection();

        // Authentification des clients externes Valora
        services.AddAuthentication()
            .AddCookie("ValoraClient", options =>
            {
                options.Cookie.Name = "Valora.Client.Auth";

                options.LoginPath = "/client/login";

                options.AccessDeniedPath = "/client/access-denied";

                options.Cookie.HttpOnly = true;

                options.Cookie.SecurePolicy =
                    CookieSecurePolicy.Always;

                options.Cookie.SameSite =
                    SameSiteMode.Lax;

                options.ExpireTimeSpan =
                    TimeSpan.FromMinutes(30);

                options.SlidingExpiration = true;
            });

        services.AddSession(options =>
        {
            options.IdleTimeout = TimeSpan.FromMinutes(1);
            options.Cookie.HttpOnly = true;
            options.Cookie.IsEssential = true;
        });
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        // Required by Wangkanai.Detection
        app.UseDetection();
        app.UseSession();

        app.UseStaticFiles();
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();

            endpoints.MapControllerRoute(
                name: "ciam",
                pattern: "ciam/{controller=Auth}/{action=SignIn}/{id?}");

            endpoints.MapContent();
        });
    }
}
