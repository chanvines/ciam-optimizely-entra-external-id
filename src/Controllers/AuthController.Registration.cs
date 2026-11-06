using System.ComponentModel.DataAnnotations;
using CiamOptimizelyPortal.Services;
using Microsoft.AspNetCore.Mvc;

namespace CiamOptimizelyPortal.Controllers;

public partial class AuthController
{
    private const string RegistrationTokenKey = "Valora:RegistrationToken";
    private const string RegistrationStepKey = "Valora:RegistrationStep";

    private async Task<IActionResult> BeginRegistrationAsync(string continuationToken)
    {
        ClearRegistration();
        if (string.IsNullOrWhiteSpace(continuationToken))
            return RegistrationFailed();

        var methods = await _mfaService.GetRegistrationMethodsAsync(continuationToken);
        if (!string.IsNullOrWhiteSpace(methods.Error) ||
            string.IsNullOrWhiteSpace(methods.ContinuationToken) ||
            methods.Methods?.Any(m => m.ChallengeChannel == "email" && m.ChallengeType == "oob") != true)
            return RegistrationFailed();

        HttpContext.Session.SetString(RegistrationTokenKey, methods.ContinuationToken);
        HttpContext.Session.SetString(RegistrationStepKey, "email");
        return Redirect("/client/mfa/register");
    }

    [HttpGet("/client/mfa/register")]
    public IActionResult RegisterMfa()
    {
        if (string.IsNullOrWhiteSpace(HttpContext.Session.GetString(RegistrationTokenKey)))
            return Redirect("/client/login");
        return RegistrationView();
    }

    [HttpPost("/client/mfa/register")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegisterMfa(string email)
    {
        var token = HttpContext.Session.GetString(RegistrationTokenKey);
        if (string.IsNullOrWhiteSpace(token) ||
            HttpContext.Session.GetString(RegistrationStepKey) != "email")
            return RegistrationExpired();

        email = email?.Trim();
        if (string.IsNullOrWhiteSpace(email) || email.Length > 254 || !new EmailAddressAttribute().IsValid(email))
            return RegistrationView("Enter a valid email address.");

        try
        {
            var result = await _mfaService.SendRegistrationChallengeAsync(token, email);
            if (!string.IsNullOrWhiteSpace(result.Error) || string.IsNullOrWhiteSpace(result.ContinuationToken))
                return RegistrationFailed();

            if (result.ChallengeType == "preverified")
                return await FinishRegistrationAsync(result.ContinuationToken, null, true);

            if (result.ChallengeType != "oob") return RegistrationFailed();
            HttpContext.Session.SetString(RegistrationTokenKey, result.ContinuationToken);
            HttpContext.Session.SetString(RegistrationStepKey, "code");
            return Redirect("/client/mfa/register");
        }
        catch (Exception ex) when (IsRegistrationTransportError(ex))
        {
            return RegistrationFailed();
        }
    }

    [HttpPost("/client/mfa/register/verify")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyMfaRegistration(string code)
    {
        var token = HttpContext.Session.GetString(RegistrationTokenKey);
        if (string.IsNullOrWhiteSpace(token) ||
            HttpContext.Session.GetString(RegistrationStepKey) != "code")
            return RegistrationExpired();

        if (string.IsNullOrWhiteSpace(code))
            return RegistrationView("Enter the verification code sent to your email.");

        try
        {
            return await FinishRegistrationAsync(token, code.Trim(), false);
        }
        catch (Exception ex) when (IsRegistrationTransportError(ex))
        {
            return RegistrationFailed();
        }
    }

    private async Task<IActionResult> FinishRegistrationAsync(string token, string code, bool preverified)
    {
        var registration = await _mfaService.CompleteRegistrationAsync(token, code, preverified);
        if (!preverified && registration.Error == "invalid_grant" && registration.SubError == "invalid_oob_value")
        {
            if (!string.IsNullOrWhiteSpace(registration.ContinuationToken))
                HttpContext.Session.SetString(RegistrationTokenKey, registration.ContinuationToken);
            return RegistrationView("That code is not valid. Please check it and try again.");
        }
        if (!string.IsNullOrWhiteSpace(registration.Error) ||
            string.IsNullOrWhiteSpace(registration.ContinuationToken))
            return RegistrationFailed();

        // Registration alone never authenticates the client. Entra must issue a valid ID token.
        ClearRegistration();
        var result = await _mfaService.GetTokensAfterRegistrationAsync(registration.ContinuationToken);
        if (result.HasIdToken && string.IsNullOrWhiteSpace(result.Error))
            return await CompleteLoginAsync(result.IdToken);

        if (result.SubError == "mfa_required" && !string.IsNullOrWhiteSpace(result.ContinuationToken))
            return await BeginMfaAsync(result.ContinuationToken);

        // Do not issue a cookie if Entra still requires another factor or another step.
        ViewBag.Message = "We could not finish signing you in. Please sign in again.";
        return View("SignIn");
    }

    private IActionResult RegistrationView(string message = null)
    {
        ViewBag.Step = HttpContext.Session.GetString(RegistrationStepKey);
        ViewBag.Message = message;
        return View("MfaRegistration");
    }

    private IActionResult RegistrationFailed()
    {
        ClearRegistration();
        ViewBag.Message = "We could not set up email verification. Please sign in and try again.";
        return View("SignIn");
    }

    private IActionResult RegistrationExpired()
    {
        ClearRegistration();
        ViewBag.Message = "Your verification session has expired. Please sign in again.";
        return View("SignIn");
    }

    private void ClearRegistration()
    {
        HttpContext.Session.Remove(RegistrationTokenKey);
        HttpContext.Session.Remove(RegistrationStepKey);
    }

    private static bool IsRegistrationTransportError(Exception exception) =>
        exception is HttpRequestException or System.Text.Json.JsonException or TaskCanceledException
            or Microsoft.IdentityModel.Tokens.SecurityTokenException;
}
