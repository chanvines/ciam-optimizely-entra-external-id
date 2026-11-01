using CiamOptimizelyPortal.Services;
using Microsoft.AspNetCore.Mvc;

namespace CiamOptimizelyPortal.Controllers;

public class PasswordResetController : Controller
{
    private readonly PasswordResetService _resetService;

    private const string TokenKey = "Valora:ResetToken";
    private const string StepKey = "Valora:ResetStep";
    private const string PollAfterKey = "Valora:PollAfter";

    public PasswordResetController(
        PasswordResetService resetService)
    {
        _resetService = resetService;
    }

    [HttpGet("/client/forgot-password")]
    public IActionResult Index()
    {
        ViewBag.Step =
            HttpContext.Session.GetString(StepKey)
            ?? "email";

        return View("ForgotPassword");
    }

    [HttpPost("/client/forgot-password/start")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Start(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return Show("email", "Enter your email address.");
        }

        ClearReset();

        try
        {
            var start =
                await _resetService.StartAsync(email);

            if (string.IsNullOrWhiteSpace(
                start.ContinuationToken))
            {
                return Show("email",
                    "Unable to start password reset.");
            }

            var challenge =
                await _resetService.ChallengeAsync(
                    start.ContinuationToken);

            if (string.IsNullOrWhiteSpace(
                challenge.ContinuationToken) ||
                challenge.ChallengeType != "oob")
            {
                return Show("email",
                    "Unable to send verification code.");
            }

            HttpContext.Session.SetString(
                TokenKey,
                challenge.ContinuationToken);

            HttpContext.Session.SetString(
                StepKey,
                "otp");

            return Redirect("/client/forgot-password");
        }
        catch (HttpRequestException)
        {
            return Show("email",
                "Password reset service is unavailable.");
        }
    }

    [HttpPost("/client/forgot-password/verify")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Verify(string code)
    {
        if (HttpContext.Session.GetString(StepKey) != "otp")
            return Redirect("/client/forgot-password");

        var token = HttpContext.Session.GetString(TokenKey);

        if (string.IsNullOrWhiteSpace(token))
            return Redirect("/client/forgot-password");

        if (string.IsNullOrWhiteSpace(code))
            return Show("otp", "Enter the verification code.");

        var result = await _resetService.ContinueAsync(
            token,
            code);

        if (string.IsNullOrWhiteSpace(
            result.ContinuationToken))
        {
            return Show("otp",
                "Invalid or expired verification code.");
        }

        HttpContext.Session.SetString(
            TokenKey,
            result.ContinuationToken);

        HttpContext.Session.SetString(
            StepKey,
            "password");

        return Redirect("/client/forgot-password");
    }

    [HttpPost("/client/forgot-password/submit")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Submit(
        string newPassword,
        string confirmPassword)
    {
        if (HttpContext.Session.GetString(StepKey) != "password")
            return Redirect("/client/forgot-password");

        var token = HttpContext.Session.GetString(TokenKey);

        if (string.IsNullOrWhiteSpace(token))
            return Redirect("/client/forgot-password");

        if (string.IsNullOrWhiteSpace(newPassword) ||
            newPassword != confirmPassword)
        {
            return Show("password",
                "Passwords do not match.");
        }

        var result = await _resetService.SubmitAsync(
            token,
            newPassword);

        if (string.IsNullOrWhiteSpace(
            result.ContinuationToken))
        {
            return Show("password",
                "The new password was not accepted.");
        }

        HttpContext.Session.SetString(
            TokenKey,
            result.ContinuationToken);

        HttpContext.Session.SetString(
            StepKey,
            "poll");

        var delay = Math.Clamp(
            result.PollInterval ?? 2,
            1,
            60);

        HttpContext.Session.SetString(
            PollAfterKey,
            DateTimeOffset.UtcNow
                .AddSeconds(delay)
                .ToUnixTimeSeconds()
                .ToString());

        return Redirect("/client/forgot-password");
    }

    [HttpPost("/client/forgot-password/status")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Status()
    {
        if (HttpContext.Session.GetString(StepKey) != "poll")
            return Redirect("/client/forgot-password");

        var token = HttpContext.Session.GetString(TokenKey);

        if (string.IsNullOrWhiteSpace(token))
            return Redirect("/client/forgot-password");

        var pollAfter =
            HttpContext.Session.GetString(PollAfterKey);

        if (long.TryParse(pollAfter, out var timestamp) &&
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() < timestamp)
        {
            return Show("poll",
                "Please wait before checking again.");
        }

        var result =
            await _resetService.PollCompletionAsync(token);

        if (result.Status == "succeeded")
        {
            ClearReset();

            return Redirect("/client/login");
        }

        if (result.Status == "failed" ||
            !string.IsNullOrWhiteSpace(result.Error))
        {
            ClearReset();

            return Show("email",
                "Password reset could not be completed.");
        }

        if (!string.IsNullOrWhiteSpace(
            result.ContinuationToken))
        {
            HttpContext.Session.SetString(
                TokenKey,
                result.ContinuationToken);
        }

        // Le prochain contrôle ne doit pas être immédiat.
        HttpContext.Session.SetString(
            PollAfterKey,
            DateTimeOffset.UtcNow
                .AddSeconds(5)
                .ToUnixTimeSeconds()
                .ToString());

        return Show("poll",
            "Password reset is still in progress.");
    }

    private IActionResult Show(
        string step,
        string message)
    {
        ViewBag.Step = step;
        ViewBag.Message = message;

        return View("ForgotPassword");
    }

    private void ClearReset()
    {
        HttpContext.Session.Remove(TokenKey);
        HttpContext.Session.Remove(StepKey);
        HttpContext.Session.Remove(PollAfterKey);
    }
}