using System.ComponentModel.DataAnnotations;
using CiamOptimizelyPortal.Services;
using Microsoft.AspNetCore.Mvc;

namespace CiamOptimizelyPortal.Controllers;

public partial class AuthController
{
    private const string SignUpTokenKey = "Valora:SignUpToken";
    private const string SignUpUnavailable = "We could not complete your registration. Please try again or contact support.";
    private const string SignUpExpired = "Your registration session expired. Please start again.";

    [HttpGet("/client/signup")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public IActionResult SignUp() => SignUpView();

    [HttpPost("/client/signup")]
    [ValidateAntiForgeryToken]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> SignUp(string firstName, string lastName, string email, string password, string confirmPassword)
    {
        HttpContext.Session.Remove(SignUpTokenKey);
        email = email?.Trim();
        firstName = firstName?.Trim();
        lastName = lastName?.Trim();

        if (string.IsNullOrWhiteSpace(firstName) || firstName.Length > 64 ||
            string.IsNullOrWhiteSpace(lastName) || lastName.Length > 64)
            return SignUpView("Enter your first and last names.");

        if (string.IsNullOrWhiteSpace(email) || email.Length > 254 || !new EmailAddressAttribute().IsValid(email))
            return SignUpView("Enter a valid email address.");

        if (string.IsNullOrWhiteSpace(password) || password.Length is < 8 or > 256)
            return SignUpView("Enter a password between 8 and 256 characters.");

        if (password != confirmPassword)
            return SignUpView("The passwords do not match.");

        try
        {
            var start = await _nativeAuthService.StartSignUpAsync(email, password, firstName, lastName);
            if (!start.CanContinue || !string.IsNullOrEmpty(start.ChallengeType))
                return SignUpView(SignUpError(start));

            var challenge = await _nativeAuthService.SendSignUpCodeAsync(start.ContinuationToken);
            if (!challenge.CanContinue || challenge.ChallengeType != "oob" || challenge.ChallengeChannel != "email")
                return SignUpView(SignUpError(challenge));

            HttpContext.Session.SetString(SignUpTokenKey, challenge.ContinuationToken);
            return Redirect("/client/signup/verify");
        }
        catch (Exception ex) when (IsRegistrationTransportError(ex))
        {
            return SignUpView(SignUpUnavailable);
        }
    }

    [HttpGet("/client/signup/verify")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public IActionResult VerifySignUp() => string.IsNullOrWhiteSpace(HttpContext.Session.GetString(SignUpTokenKey))
        ? SignUpView(SignUpExpired)
        : SignUpView(verifyCode: true);

    [HttpPost("/client/signup/verify")]
    [ValidateAntiForgeryToken]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> VerifySignUp(string code)
    {
        var token = HttpContext.Session.GetString(SignUpTokenKey);
        if (string.IsNullOrWhiteSpace(token))
            return SignUpView(SignUpExpired);

        code = code?.Trim();
        if (string.IsNullOrWhiteSpace(code) || code.Length > 32)
            return SignUpView("Enter the verification code from your email.", verifyCode: true);

        try
        {
            var result = await _nativeAuthService.VerifySignUpCodeAsync(token, code);
            if (result.Error == "invalid_grant" && result.SubError == "invalid_oob_value")
            {
                if (!string.IsNullOrWhiteSpace(result.ContinuationToken))
                    HttpContext.Session.SetString(SignUpTokenKey, result.ContinuationToken);
                return SignUpView("That verification code is incorrect. Please try again.", verifyCode: true);
            }

            HttpContext.Session.Remove(SignUpTokenKey);
            if (!result.CanContinue || !string.IsNullOrEmpty(result.ChallengeType))
                return SignUpView(SignUpError(result));

            TempData["SignUpSuccess"] = "Your account is ready. Sign in with your email and password.";
            return Redirect("/client/login");
        }
        catch (Exception ex) when (IsRegistrationTransportError(ex))
        {
            return SignUpView("We could not confirm registration. Try signing in or verify the code again.", verifyCode: true);
        }
    }

    private IActionResult SignUpView(string message = null, bool verifyCode = false)
    {
        ViewBag.Message = message;
        ViewBag.VerifyCode = verifyCode;
        return View("SignUp");
    }

    private static string SignUpError(SignUpResponse response) => response.Error switch
    {
        "expired_token" => SignUpExpired,
        "invalid_grant" when response.SubError is "password_too_weak" or "password_too_short" or
            "password_too_long" or "password_banned" or "password_is_invalid" or "password_recently_used"
            => "Choose a different password that meets the security requirements.",
        _ => SignUpUnavailable
    };
}
