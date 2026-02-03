using System.Text.Encodings.Web;
using System.Security.Cryptography.Xml;
using Newtonsoft.Json;
using log4net;

namespace VulnerableApp;

/// <summary>
/// Demo .NET application with intentional vulnerabilities for testing DepGuard
/// DO NOT USE IN PRODUCTION - Contains known vulnerable packages
/// </summary>
public class Program
{
    private static readonly ILog _logger = LogManager.GetLogger(typeof(Program));

    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var app = builder.Build();

        // REACHABLE: Uses vulnerable System.Text.Encodings.Web
        app.MapGet("/encode", (string input) =>
        {
            var encoder = HtmlEncoder.Default;
            return encoder.Encode(input);  // CVE-2022-29117
        });

        // REACHABLE: Uses vulnerable Newtonsoft.Json
        app.MapPost("/deserialize", (HttpContext context) =>
        {
            using var reader = new StreamReader(context.Request.Body);
            var json = reader.ReadToEndAsync().Result;
            var obj = JsonConvert.DeserializeObject<dynamic>(json);  // Potential deserialization issues
            return Results.Ok(obj);
        });

        // REACHABLE: Uses vulnerable log4net
        app.MapGet("/log", (string message) =>
        {
            _logger.Info(message);  // CVE-2018-1285
            return Results.Ok("Logged");
        });

        // NOT REACHABLE: Vulnerable code in unused function
        app.MapGet("/health", () => Results.Ok("Healthy"));

        app.Run();
    }

    // NOT REACHABLE: This vulnerable function is never called
    private static void UnusedVulnerableFunction()
    {
        var signedXml = new SignedXml();  // CVE-2022-34716
        // This code path is never executed
    }
}
