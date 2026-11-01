using CiamOptimizelyPortal.Services;
using Microsoft.AspNetCore.Mvc;

namespace CiamOptimizelyPortal.Controllers;

public class PasswordResetController : Controller
{
    private readonly PasswordResetService _resetService;

    private const string TokenKey = "Valora:ResetToken";
    private const string StepKey = "Valora:ResetStep";
    private const string PollAfterKey = "Valora:PollAfter";
    private const string PollIntervalKey = "Valora:PollInterval";
    private const string PollDeadlineKey = "Valora:PollDeadline";

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
        SetPollDelay();

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

        var delay = Math.Max(result.PollInterval ?? 2, 1);
        HttpContext.Session.SetInt32(PollIntervalKey, delay);
        HttpContext.Session.SetString(PollDeadlineKey,
            DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeSeconds().ToString());

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

        if (!long.TryParse(HttpContext.Session.GetString(PollDeadlineKey), out var deadline) ||
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() >= deadline)
        {
            ClearReset();
            return Show("email", "We could not confirm your password reset in time. Try signing in with your new password, or start again.");
        }

        var pollAfter =
            HttpContext.Session.GetString(PollAfterKey);

        if (long.TryParse(pollAfter, out var timestamp) &&
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() < timestamp)
        {
            return Show("poll",
                "Please wait before checking again.");
        }

        PasswordResetResponse result;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(HttpContext.RequestAborted);
            timeout.CancelAfter(TimeSpan.FromSeconds(Math.Max(1,
                deadline - DateTimeOffset.UtcNow.ToUnixTimeSeconds())));
            result = await _resetService.PollCompletionAsync(token, timeout.Token);
        }
        catch (Exception ex) when (ex is HttpRequestException ||
            ex is System.Text.Json.JsonException || ex is TaskCanceledException)
        {
            ClearReset();
            return Show("email", "We could not confirm your password reset. Please try signing in, or start again.");
        }

        if (result.Status == "succeeded")
        {
            ClearReset();
            TempData["PasswordResetSuccess"] = "Password reset completed. Sign in with your new password.";

            return Redirect("/client/login");
        }

        if (result.Status == "failed" ||
            !string.IsNullOrWhiteSpace(result.Error))
        {
            ClearReset();

            return Show("email",
                "Password reset could not be completed.");
        }

        if (result.Status != "in_progress" && result.Status != "not_started")
        {
            ClearReset();
            return Show("email", "We could not confirm your password reset. Please try signing in, or start again.");
        }

        if (!string.IsNullOrWhiteSpace(
            result.ContinuationToken))
        {
            HttpContext.Session.SetString(
                TokenKey,
                result.ContinuationToken);
        }

        // Le prochain contrôle ne doit pas être immédiat.
        var interval = Math.Max(result.PollInterval ??
            HttpContext.Session.GetInt32(PollIntervalKey) ?? 2, 1);
        HttpContext.Session.SetInt32(PollIntervalKey, interval);
        HttpContext.Session.SetString(
            PollAfterKey,
            DateTimeOffset.UtcNow
                .AddSeconds(interval)
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
        SetPollDelay();

        return View("ForgotPassword");
    }

    private void ClearReset()
    {
        HttpContext.Session.Remove(TokenKey);
        HttpContext.Session.Remove(StepKey);
        HttpContext.Session.Remove(PollAfterKey);
        HttpContext.Session.Remove(PollIntervalKey);
        HttpContext.Session.Remove(PollDeadlineKey);
    }

    private void SetPollDelay()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long.TryParse(HttpContext.Session.GetString(PollAfterKey), out var next);
        long.TryParse(HttpContext.Session.GetString(PollDeadlineKey), out var deadline);
        ViewBag.PollDelayMs = Math.Max(1, Math.Min(next - now, deadline - now)) * 1000;
    }
}
