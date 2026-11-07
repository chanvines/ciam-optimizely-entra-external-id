using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using CiamOptimizelyPortal.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;

namespace CiamOptimizelyPortal.Controllers;

public partial class AuthController
{
    private const string SignUpStateKey = "Valora:SignUp";
    private const string PendingLinkCookie = "__Host-Valora.PendingLink";
    private const string SignUpUnavailable = "We could not complete your registration. Please try again or contact support.";
    private const string SignUpExpired = "Your registration session expired. Please start again.";

    [HttpGet("/client/signup")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public IActionResult SignUp() => SignUpView();

    [HttpPost("/client/signup")]
    [ValidateAntiForgeryToken]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> SignUp(string email)
    {
        HttpContext.Session.Remove(SignUpStateKey);
        email = email?.Trim();
        if (string.IsNullOrWhiteSpace(email) || email.Length > 254 || !new EmailAddressAttribute().IsValid(email))
            return SignUpView("Enter a valid email address.");

        if (!_salesforceContacts.IsConfigured)
            return SignUpView(SignUpUnavailable);

        try
        {
            var start = await _nativeAuthService.StartSignUpAsync(email);
            if (!start.CanContinue || !string.IsNullOrEmpty(start.ChallengeType))
                return SignUpView(SignUpError(start));

            var challenge = await _nativeAuthService.RequestSignUpChallengeAsync(start.ContinuationToken);
            if (!challenge.CanContinue || challenge.ChallengeType != "oob" || challenge.ChallengeChannel != "email")
                return SignUpView(SignUpError(challenge));

            SaveSignUpState(new(email, challenge.ContinuationToken));
            return Redirect("/client/signup/verify");
        }
        catch (Exception ex) when (IsRegistrationTransportError(ex))
        {
            return SignUpView(SignUpUnavailable);
        }
    }

    [HttpGet("/client/signup/verify")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public IActionResult VerifySignUp() => GetSignUpState() is { Contact: null }
        ? SignUpView(step: "code")
        : SignUpView(SignUpExpired);

    [HttpPost("/client/signup/verify")]
    [ValidateAntiForgeryToken]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> VerifySignUp(string code)
    {
        var state = GetSignUpState();
        if (state is not { Contact: null })
            return SignUpView(SignUpExpired);

        code = code?.Trim();
        if (string.IsNullOrWhiteSpace(code) || code.Length > 32)
            return SignUpView("Enter the verification code from your email.", "code");

        try
        {
            var result = await _nativeAuthService.VerifySignUpCodeAsync(state.Token, code);
            if (result.Error == "invalid_grant" && result.SubError == "invalid_oob_value")
            {
                if (!string.IsNullOrWhiteSpace(result.ContinuationToken))
                    SaveSignUpState(state with { Token = result.ContinuationToken });
                return SignUpView("That verification code is incorrect. Please try again.", "code");
            }

            HttpContext.Session.Remove(SignUpStateKey);
            if (result.Error != "credential_required" || string.IsNullOrWhiteSpace(result.ContinuationToken))
                return SignUpView(SignUpError(result));

            var contact = await _salesforceContacts.FindByEmailAsync(state.Email, HttpContext.RequestAborted);
            if (!CanRegisterContact(contact, state.Email))
                return SignUpView(SignUpUnavailable);

            SaveSignUpState(state with { Token = result.ContinuationToken, Contact = contact });
            return Redirect("/client/signup/profile");
        }
        catch (Exception ex) when (IsRegistrationTransportError(ex))
        {
            return SignUpView(SignUpUnavailable);
        }
    }

    [HttpGet("/client/signup/profile")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public IActionResult SignUpProfile() => GetSignUpState() is { Contact: not null } state
        ? SignUpView(step: "profile", contact: state.Contact)
        : SignUpView(SignUpExpired);

    [HttpPost("/client/signup/profile")]
    [ValidateAntiForgeryToken]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> ConfirmSignUpProfile()
    {
        var state = GetSignUpState();
        if (state is not { Contact: not null, PasswordStep: false })
            return SignUpView(SignUpExpired);

        try
        {
            var challenge = await _nativeAuthService.RequestSignUpChallengeAsync(state.Token);
            if (!challenge.CanContinue || challenge.ChallengeType != "password")
                return SignUpView(SignUpError(challenge));

            SaveSignUpState(state with { Token = challenge.ContinuationToken, PasswordStep = true });
            return Redirect("/client/signup/password");
        }
        catch (Exception ex) when (IsRegistrationTransportError(ex))
        {
            return SignUpView(SignUpUnavailable);
        }
    }

    [HttpGet("/client/signup/password")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public IActionResult SignUpPassword() => GetSignUpState() is { PasswordStep: true }
        ? SignUpView(step: "password")
        : SignUpView(SignUpExpired);

    [HttpPost("/client/signup/password")]
    [ValidateAntiForgeryToken]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> SignUpPassword(string password, string confirmPassword)
    {
        var state = GetSignUpState();
        if (state is not { Contact: not null, PasswordStep: true })
            return SignUpView(SignUpExpired);

        if (string.IsNullOrWhiteSpace(password) || password.Length is < 8 or > 256)
            return SignUpView("Enter a password between 8 and 256 characters.", "password");
        if (password != confirmPassword)
            return SignUpView("The passwords do not match.", "password");

        try
        {
            var contact = await _salesforceContacts.FindByEmailAsync(state.Email, HttpContext.RequestAborted);
            if (!CanRegisterContact(contact, state.Email) || contact.Id != state.Contact.Id ||
                contact.FirstName != state.Contact.FirstName || contact.LastName != state.Contact.LastName)
            {
                HttpContext.Session.Remove(SignUpStateKey);
                return SignUpView(SignUpUnavailable);
            }

            var result = await _nativeAuthService.SubmitSignUpPasswordAsync(state.Token, password);
            if (IsPasswordPolicyError(result))
            {
                if (!string.IsNullOrWhiteSpace(result.ContinuationToken))
                    SaveSignUpState(state with { Token = result.ContinuationToken });
                return SignUpView(SignUpError(result), "password");
            }

            HttpContext.Session.Remove(SignUpStateKey);
            if (result.Error != "attributes_required" || string.IsNullOrWhiteSpace(result.ContinuationToken))
                return SignUpView(SignUpError(result));

            var profile = await _nativeAuthService.SubmitSignUpAttributesAsync(result.ContinuationToken, contact);
            if (!profile.CanContinue || !string.IsNullOrEmpty(profile.ChallengeType))
                return SignUpView(SignUpError(profile));

            SavePendingLink(new(state.Email, contact.Id));
            TempData["SignUpSuccess"] = "Your account is ready. Sign in to complete verification.";
            return Redirect("/client/login");
        }
        catch (Exception ex) when (IsRegistrationTransportError(ex))
        {
            HttpContext.Session.Remove(SignUpStateKey);
            return SignUpView(SignUpUnavailable);
        }
    }

    private static bool CanRegisterContact(SalesforceContact contact, string email) =>
        contact is { IsActive: true } && string.IsNullOrWhiteSpace(contact.EntraObjectId) &&
        string.Equals(contact.Email, email, StringComparison.OrdinalIgnoreCase) &&
        contact.FirstName?.Trim().Length is > 0 and <= 64 &&
        contact.LastName?.Trim().Length is > 0 and <= 64;

    private SignUpState GetSignUpState() => HttpContext.Session.GetString(SignUpStateKey) is { } json
        ? JsonSerializer.Deserialize<SignUpState>(json)
        : null;

    private void SaveSignUpState(SignUpState state) =>
        HttpContext.Session.SetString(SignUpStateKey, JsonSerializer.Serialize(state));

    private void SavePendingLink(PendingLink link)
    {
        var value = _pendingLinkProtector.Protect(JsonSerializer.Serialize(link), TimeSpan.FromDays(1));
        Response.Cookies.Append(PendingLinkCookie, value, PendingLinkCookieOptions());
    }

    private static CookieOptions PendingLinkCookieOptions() => new()
    {
        Path = "/", HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, MaxAge = TimeSpan.FromDays(1)
    };

    private IActionResult SignUpView(string message = null, string step = "email", SalesforceContact contact = null)
    {
        ViewBag.Message = message;
        ViewBag.Step = step;
        return View("SignUp", contact);
    }

    private static bool IsPasswordPolicyError(SignUpResponse response) =>
        response.Error == "invalid_grant" && response.SubError is "password_too_weak" or "password_too_short" or
            "password_too_long" or "password_banned" or "password_is_invalid" or "password_recently_used";

    private static string SignUpError(SignUpResponse response) => response.Error == "expired_token"
        ? SignUpExpired
        : IsPasswordPolicyError(response) ? "Choose a different password that meets the security requirements." : SignUpUnavailable;

    private sealed record SignUpState(string Email, string Token, SalesforceContact Contact = null, bool PasswordStep = false);
    private sealed record PendingLink(string Email, string ContactId);
}
