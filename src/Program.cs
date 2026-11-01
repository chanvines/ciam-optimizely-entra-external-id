namespace CiamOptimizelyPortal;

public class Program
{
    public static void Main(string[] args) => CreateHostBuilder(args).Build().Run();

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureCmsDefaults()
            .ConfigureAppConfiguration((context, config) =>
            {
                config.AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: true);
                config.AddEnvironmentVariables();
                if (args.Length > 0) config.AddCommandLine(args);
            })
            .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
}
