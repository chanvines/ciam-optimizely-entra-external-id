using System.Net;
using System.Text;
using CiamOptimizelyPortal.Controllers;
using CiamOptimizelyPortal.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Logging.Abstractions;

static void Check(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

static (PasswordResetController Controller, StubHandler Handler, ISession Session) Create(string json)
{
    var handler = new StubHandler(json);
    var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string>
    {
        ["EntraExternal:TenantSubdomain"] = "example",
        ["EntraExternal:ClientId"] = "example-client"
    }).Build();
    var service = new PasswordResetService(new HttpClient(handler), config,
        NullLogger<PasswordResetService>.Instance);
    var context = new DefaultHttpContext { Session = new MemorySession() };
    var controller = new PasswordResetController(service)
    {
        ControllerContext = new ControllerContext { HttpContext = context },
        TempData = new TempDataDictionary(context, new EmptyTempData())
    };
    context.Session.SetString("Valora:ResetStep", "poll");
    context.Session.SetString("Valora:ResetToken", "test-token");
    context.Session.SetString("Valora:PollDeadline", DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeSeconds().ToString());
    return (controller, handler, context.Session);
}

var success = Create("{\"status\":\"succeeded\"}");
Check(await success.Controller.Status() is RedirectResult { Url: "/client/login" }, "Success must return to sign-in.");
Check(success.Controller.TempData.ContainsKey("PasswordResetSuccess"), "Success must show confirmation.");
Check(success.Session.GetString("Valora:ResetToken") == null, "Success must clear reset token.");

var pending = Create("{\"status\":\"in_progress\",\"continuation_token\":\"next-token\"}");
pending.Session.SetInt32("Valora:PollInterval", 9);
Check(await pending.Controller.Status() is ViewResult, "Pending must continue automatically.");
Check(pending.Session.GetString("Valora:ResetToken") == "next-token", "Continuation token must rotate.");
var next = long.Parse(pending.Session.GetString("Valora:PollAfter"));
Check(next >= DateTimeOffset.UtcNow.AddSeconds(8).ToUnixTimeSeconds(), "Must respect Entra polling interval.");
await pending.Controller.Status();
Check(pending.Handler.Calls == 1, "Early polls must not call Entra again.");

var expired = Create("{\"status\":\"succeeded\"}");
expired.Session.SetString("Valora:PollDeadline", "0");
Check(await expired.Controller.Status() is ViewResult, "Deadline must show recovery message.");
Check(expired.Handler.Calls == 0, "Expired operation must not call Entra.");
Check(expired.Session.GetString("Valora:ResetToken") == null, "Timeout must clear reset token.");

foreach (var json in new[] { "{\"status\":\"failed\"}", "{}", "{\"error\":\"expired_token\"}", "not json" })
{
    var failed = Create(json);
    Check(await failed.Controller.Status() is ViewResult, "Errors must show recovery.");
    Check(!failed.Controller.TempData.ContainsKey("PasswordResetSuccess"), "Errors must never show success.");
    Check(failed.Session.GetString("Valora:ResetToken") == null, "Errors must clear reset token.");
}

var submit = Create("{\"continuation_token\":\"submitted-token\",\"poll_interval\":12}");
submit.Session.SetString("Valora:ResetStep", "password");
Check(await submit.Controller.Submit("example-password", "example-password") is RedirectResult,
    "Password submission must redirect to progress page.");
Check(submit.Session.GetInt32("Valora:PollInterval") == 12, "Submission must retain server interval.");
Check(submit.Session.GetString("Valora:ResetStep") == "poll", "Submission must enter polling state.");
Console.WriteLine("Password reset checks passed: success, pending, interval, timeout, failures and submission.");

sealed class StubHandler(string json) : HttpMessageHandler
{
    public int Calls { get; private set; }
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Calls++;
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StringContent(json, Encoding.UTF8, "application/json") });
    }
}

sealed class MemorySession : ISession
{
    private readonly Dictionary<string, byte[]> values = new();
    public bool IsAvailable => true;
    public string Id => "test-session";
    public IEnumerable<string> Keys => values.Keys;
    public void Clear() => values.Clear();
    public void Remove(string key) => values.Remove(key);
    public void Set(string key, byte[] value) => values[key] = value;
    public bool TryGetValue(string key, out byte[] value) => values.TryGetValue(key, out value);
    public Task LoadAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task CommitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
}

sealed class EmptyTempData : ITempDataProvider
{
    public IDictionary<string, object> LoadTempData(HttpContext context) => new Dictionary<string, object>();
    public void SaveTempData(HttpContext context, IDictionary<string, object> values) { }
}
