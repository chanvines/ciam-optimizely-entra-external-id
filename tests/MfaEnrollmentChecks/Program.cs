using System.Net;
using System.Security.Claims;
using CiamOptimizelyPortal.Controllers;
using CiamOptimizelyPortal.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

static void Check(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}
static (AuthController Controller, StubHandler Handler, MemorySession Session, NoSignIn Auth, TestValidator Validator) Create(params string[] responses)
{
    var handler = new StubHandler(responses);
    var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string>
    {
        ["EntraExternal:TenantSubdomain"] = "example",
        ["EntraExternal:ClientId"] = "test-client"
    }).Build();
    var session = new MemorySession();
    var auth = new NoSignIn();
    var context = new DefaultHttpContext
    {
        Session = session,
        RequestServices = new ServiceCollection().AddSingleton<IAuthenticationService>(auth).BuildServiceProvider()
    };
    var client = new HttpClient(handler);
    var validator = new TestValidator();
    var controller = new AuthController(new NativeAuthService(client, config, NullLogger<NativeAuthService>.Instance),
        new MfaService(client, config), validator)
    {
        ControllerContext = new ControllerContext { HttpContext = context },
        TempData = new TempDataDictionary(context, new EmptyTempData())
    };
    return (controller, handler, session, auth, validator);
}
static void SetStep(MemorySession session, string step)
{
    session.SetString("Valora:RegistrationToken", "test-token");
    session.SetString("Valora:RegistrationStep", step);
}

var start = Create(
    "{\"continuation_token\":\"init\"}",
    "{\"continuation_token\":\"password\",\"challenge_type\":\"password\"}",
    "{\"error\":\"invalid_grant\",\"suberror\":\"registration_required\",\"continuation_token\":\"reg\"}",
    "{\"continuation_token\":\"methods\",\"methods\":[{\"id\":\"email\",\"challenge_type\":\"oob\",\"challenge_channel\":\"email\"}]}");
Check(await start.Controller.SignIn("test@example.com", "example-password") is RedirectResult { Url: "/client/mfa/register" },
    "registration_required must start registration.");
Check(start.Session.GetString("Valora:RegistrationToken") == "methods", "Must use rotated registration token.");
Check(start.Auth.SignIns == 0, "Registration must not issue a cookie.");
Check(start.Handler.Requests.Last().Path == "/example.onmicrosoft.com/register/v1.0/introspect", "Must introspect registration methods.");

var challenge = Create("{\"challenge_type\":\"oob\",\"continuation_token\":\"challenge-token\"}");
SetStep(challenge.Session, "email");
Check(await challenge.Controller.RegisterMfa("not-an-email") is ViewResult, "Invalid email must stay on form.");
Check(challenge.Handler.Requests.Count == 0, "Invalid email must not call Entra.");
Check(await challenge.Controller.RegisterMfa("test@example.com") is RedirectResult, "Challenge must move to code step.");
Check(challenge.Session.GetString("Valora:RegistrationStep") == "code", "Must require verification code.");
Check(challenge.Handler.Requests[0].Body.Contains("challenge_target=test%40example.com"), "Must send email as challenge target.");

var verify = Create(
    "{\"continuation_token\":\"registered\"}",
    "{\"error\":\"invalid_grant\",\"suberror\":\"mfa_required\",\"continuation_token\":\"extra-factor\"}",
    "{\"continuation_token\":\"methods\",\"methods\":[{\"id\":\"email\",\"challenge_type\":\"oob\",\"challenge_channel\":\"email\"}]}",
    "{\"continuation_token\":\"mfa-token\",\"challenge_type\":\"oob\"}");
SetStep(verify.Session, "code");
Check(await verify.Controller.VerifyMfaRegistration("12345678") is RedirectResult { Url: "/client/mfa" },
    "Additional MFA must continue seamlessly instead of issuing a cookie.");
Check(verify.Handler.Requests[0].Body.Contains("grant_type=oob"), "Code registration must use oob grant.");
Check(verify.Handler.Requests[1].Body.Contains("grant_type=continuation_token"), "Must request tokens after registration.");
Check(verify.Auth.SignIns == 0, "An extra authentication requirement must never issue a cookie.");
Check(verify.Session.GetString("Valora:RegistrationToken") == null, "Registration token must be cleared after completion.");

var preverified = Create(
    "{\"challenge_type\":\"preverified\",\"continuation_token\":\"preverified-token\"}",
    "{\"continuation_token\":\"registered\"}",
    "{\"error\":\"invalid_grant\"}");
SetStep(preverified.Session, "email");
await preverified.Controller.RegisterMfa("test@example.com");
Check(preverified.Handler.Requests[1].Body.Contains("grant_type=continuation_token"), "Preverified method must use continuation_token grant.");
Check(!preverified.Handler.Requests[1].Body.Contains("oob="), "Preverified method must not send an invented OTP.");
Check(preverified.Auth.SignIns == 0, "Registration success without ID token must not sign in.");

foreach (var body in new[] { "{}", "{\"error\":\"invalid_grant\"}", "invalid-json" })
{
    var failed = Create(body);
    SetStep(failed.Session, "code");
    Check(await failed.Controller.VerifyMfaRegistration("12345678") is ViewResult, "Errors must show controlled recovery.");
    Check(failed.Auth.SignIns == 0, "Error must never issue a cookie.");
    Check(failed.Session.GetString("Valora:RegistrationToken") == null, "Error must clear unfinished registration.");
}
var expired = Create();
Check(expired.Controller.RegisterMfa() is RedirectResult { Url: "/client/login" }, "Direct GET must not start enrollment.");
await expired.Controller.VerifyMfaRegistration("12345678");
Check(expired.Handler.Requests.Count == 0, "Expired enrollment must not call Entra.");

var wrongCode = Create("{\"error\":\"invalid_grant\",\"suberror\":\"invalid_oob_value\"}");
SetStep(wrongCode.Session, "code");
Check(await wrongCode.Controller.VerifyMfaRegistration("00000000") is ViewResult, "Wrong code must allow correction.");
Check(wrongCode.Session.GetString("Valora:RegistrationStep") == "code" && wrongCode.Auth.SignIns == 0,
    "Wrong code must preserve verification state without signing in.");

var httpError = Create("{\"continuation_token\":\"untrusted\"}");
httpError.Handler.Status = HttpStatusCode.InternalServerError;
SetStep(httpError.Session, "code");
await httpError.Controller.VerifyMfaRegistration("12345678");
Check(httpError.Handler.Requests.Count == 1 && httpError.Auth.SignIns == 0, "HTTP error must not advance registration.");

var success = Create("{\"continuation_token\":\"registered\"}", "{\"id_token\":\"test-id-token\"}");
SetStep(success.Session, "code");
Check(await success.Controller.VerifyMfaRegistration("12345678") is RedirectResult { Url: "/client/my-account" },
    "Validated ID token must complete sign-in.");
Check(success.Validator.Calls == 1 && success.Auth.SignIns == 1, "ID token validation must precede cookie creation.");

var invalidToken = Create("{\"continuation_token\":\"registered\"}", "{\"id_token\":\"test-invalid-token\"}");
SetStep(invalidToken.Session, "code");
invalidToken.Validator.Reject = true;
Check(await invalidToken.Controller.VerifyMfaRegistration("12345678") is ViewResult, "Invalid ID token must return to sign-in.");
Check(invalidToken.Auth.SignIns == 0 && invalidToken.Validator.Calls == 1, "Rejected ID token must never create a cookie.");
Console.WriteLine("MFA enrollment checks passed: registration, validation, extra factor, preverified, failure, expiry and HTTP errors.");

var signup = Create(
    """{"continuation_token":"signup-start"}""",
    """{"continuation_token":"signup-code","challenge_type":"oob","challenge_channel":"email"}""",
    """{"error":"invalid_grant","suberror":"invalid_oob_value","continuation_token":"signup-retry"}""",
    """{"continuation_token":"signup-complete"}""");
Check(await signup.Controller.SignUp("Example", "Client", "test@example.com", "example-password", "different") is ViewResult &&
    signup.Handler.Requests.Count == 0, "Mismatched passwords must not call Entra.");
Check(await signup.Controller.SignUp("Example", "Client", "test@example.com", "example-password", "example-password")
    is RedirectResult { Url: "/client/signup/verify" }, "Successful signup challenge must show the code form.");
Check(signup.Handler.Requests[0].Path.EndsWith("/signup/v1.0/start") &&
    signup.Handler.Requests[0].Body.Contains("challenge_type=oob+password+redirect") &&
    signup.Handler.Requests[0].Body.Contains("attributes="), "Signup must submit the supported challenges and profile attributes.");
Check(signup.Handler.Requests[1].Path.EndsWith("/signup/v1.0/challenge") &&
    signup.Handler.Requests[1].Body.Contains("continuation_token=signup-start"), "Challenge must use the start token.");
Check(await signup.Controller.VerifySignUp("00000000") is ViewResult &&
    signup.Session.GetString("Valora:SignUpToken") == "signup-retry", "A wrong code must allow retry with the latest token.");
Check(await signup.Controller.VerifySignUp("12345678") is RedirectResult { Url: "/client/login" } &&
    signup.Controller.TempData.ContainsKey("SignUpSuccess") &&
    signup.Auth.SignIns == 0, "Confirmed signup must direct the client to sign in.");
Check(signup.Handler.Requests[3].Path.EndsWith("/signup/v1.0/continue") &&
    signup.Handler.Requests[3].Body.Contains("continuation_token=signup-retry") &&
    signup.Handler.Requests[3].Body.Contains("grant_type=oob"), "Verification must submit the code with the latest token.");
Check(await signup.Controller.VerifySignUp("12345678") is ViewResult &&
    signup.Handler.Requests.Count == 4, "A completed or missing session must not submit the code again.");
var incomplete = Create("""{"error":"attributes_required","continuation_token":"more-attributes"}""");
incomplete.Session.SetString("Valora:SignUpToken", "signup-code");
Check(await incomplete.Controller.VerifySignUp("12345678") is ViewResult &&
    !incomplete.Controller.TempData.ContainsKey("SignUpSuccess") &&
    incomplete.Session.GetString("Valora:SignUpToken") == null, "Additional required attributes must prevent a false confirmation.");
Console.WriteLine("Signup checks passed: validation, email challenge, code retry, completion and missing session.");

sealed class StubHandler(params string[] responses) : HttpMessageHandler
{
    private readonly Queue<string> queue = new(responses);
    public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;
    public List<(string Path, string Body)> Requests { get; } = new();
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add((request.RequestUri.AbsolutePath, await request.Content.ReadAsStringAsync(cancellationToken)));
        var body = queue.Dequeue();
        var status = Status == HttpStatusCode.OK && body.Contains("\"error\"")
            ? HttpStatusCode.BadRequest : Status;
        return new HttpResponseMessage(status) { Content = new StringContent(body) };
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
sealed class NoSignIn : IAuthenticationService
{
    public int SignIns { get; private set; }
    public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string scheme) => Task.FromResult(AuthenticateResult.NoResult());
    public Task ChallengeAsync(HttpContext context, string scheme, AuthenticationProperties properties) => Task.CompletedTask;
    public Task ForbidAsync(HttpContext context, string scheme, AuthenticationProperties properties) => Task.CompletedTask;
    public Task SignInAsync(HttpContext context, string scheme, ClaimsPrincipal principal, AuthenticationProperties properties)
    { SignIns++; return Task.CompletedTask; }
    public Task SignOutAsync(HttpContext context, string scheme, AuthenticationProperties properties) => Task.CompletedTask;
}
sealed class TestValidator : ITokenValidationService
{
    public int Calls { get; private set; }
    public bool Reject { get; set; }
    public Task<ClaimsPrincipal> ValidateAsync(string idToken)
    {
        Calls++;
        if (Reject) throw new Microsoft.IdentityModel.Tokens.SecurityTokenException("Test rejection.");
        return Task.FromResult(new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim("sub", "test-subject"), new Claim("name", "Test Client")
        }, "test")));
    }
}
