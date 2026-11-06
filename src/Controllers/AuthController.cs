using Microsoft.AspNetCore.Mvc;
using CiamOptimizelyPortal.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace CiamOptimizelyPortal.Controllers;

public partial class AuthController : Controller
{
	private readonly NativeAuthService _nativeAuthService;
	private readonly MfaService _mfaService;
	private readonly ITokenValidationService _tokenValidationService;

	public AuthController(
		NativeAuthService nativeAuthService,
		MfaService mfaService,
		ITokenValidationService tokenValidationService)
	{
		_nativeAuthService = nativeAuthService;
		_mfaService = mfaService;
		_tokenValidationService = tokenValidationService;
	}

	[HttpGet("/client/login")]
	public IActionResult SignIn()
	{
		ViewBag.Message = TempData["PasswordResetSuccess"];
		return View();
	}

	[HttpPost("/client/login")]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> SignIn(
	string email,
	string password)
	{
		if (string.IsNullOrWhiteSpace(email) ||
			string.IsNullOrWhiteSpace(password))
		{
			ViewBag.Message =
				"Please enter your email and password.";

			return View();
		}

		HttpContext.Session.Remove("Valora:MfaToken");
		ClearRegistration();

		try
		{
			var result =
				await _nativeAuthService.TestSignInAsync(
					email,
					password);

			// Authentification complète sans MFA supplémentaire
			if (result.HasIdToken && string.IsNullOrWhiteSpace(result.Error))
			{
				return await CompleteLoginAsync(
					result.IdToken);
			}

			// MFA obligatoire
			if (result.SubError == "mfa_required" &&
				!string.IsNullOrWhiteSpace(
					result.ContinuationToken))
			{
				return await BeginMfaAsync(result.ContinuationToken);
			}

			// Enregistrement MFA requis
			if (result.SubError == "registration_required")
			{
				return await BeginRegistrationAsync(result.ContinuationToken);
			}

			ViewBag.Message =
				"Authentication failed. Please check your credentials.";

			return View();
		}
		catch (Exception ex) when (IsRegistrationTransportError(ex))
		{
			ViewBag.Message =
				"Unable to complete authentication.";

			return View();
		}
	}

	[HttpGet("/client/mfa")]
	public IActionResult Mfa()
	{
		var continuationToken =
			HttpContext.Session.GetString("Valora:MfaToken");

		if (string.IsNullOrWhiteSpace(continuationToken))
			return Redirect("/client/login");

		return View();
	}

	[HttpPost("/client/mfa")]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> Mfa(string code)
	{
		var continuationToken =
			HttpContext.Session.GetString("Valora:MfaToken");

		if (string.IsNullOrWhiteSpace(continuationToken))
			return Redirect("/client/login");

		if (string.IsNullOrWhiteSpace(code))
		{
			ViewBag.Message = "Please enter your verification code.";
			return View();
		}

		try
		{
			var result = await _mfaService.VerifyCodeAsync(continuationToken, code.Trim());

			if (result.HasIdToken && string.IsNullOrWhiteSpace(result.Error))
			{
				return await CompleteLoginAsync(result.IdToken);
			}
		}
		catch (Exception ex) when (IsRegistrationTransportError(ex))
		{
			// Fail closed and discard the unfinished challenge below.
		}

		// Un autre défi peut être demandé.
		// Ne jamais authentifier l'utilisateur dans ce cas.
		HttpContext.Session.Remove("Valora:MfaToken");

		ViewBag.Message =
			"Verification failed or another authentication step is required.";

		return View();
	}

	private async Task<IActionResult> BeginMfaAsync(string continuationToken)
	{
		var methods = await _mfaService.GetMethodsAsync(continuationToken);
		var method = methods.Methods?.FirstOrDefault(m =>
			m.ChallengeType == "oob" && m.ChallengeChannel == "email" && !string.IsNullOrWhiteSpace(m.Id));
		if (method == null || !string.IsNullOrWhiteSpace(methods.Error) ||
			string.IsNullOrWhiteSpace(methods.ContinuationToken))
		{
			ViewBag.Message = "No supported verification method is available. Please contact support.";
			return View("SignIn");
		}
		var challenge = await _mfaService.SendChallengeAsync(methods.ContinuationToken, method.Id);
		if (!string.IsNullOrWhiteSpace(challenge.Error) || challenge.ChallengeType != "oob" ||
			string.IsNullOrWhiteSpace(challenge.ContinuationToken))
		{
			ViewBag.Message = "We could not send your verification code. Please sign in and try again.";
			return View("SignIn");
		}
		HttpContext.Session.SetString("Valora:MfaToken", challenge.ContinuationToken);
		return Redirect("/client/mfa");
	}
	[HttpGet("/client/signup")]
	public IActionResult SignUp()
	{
		return View();
	}
	
	private async Task<IActionResult> CompleteLoginAsync(
	string idToken)
	{
		ClaimsPrincipal validatedPrincipal;

		try
		{
			validatedPrincipal =
				await _tokenValidationService.ValidateAsync(idToken);
		}
		catch (SecurityTokenException)
		{
			ViewBag.Message =
				"Authentication token validation failed.";

			return View("SignIn");
		}

		var subject =
			validatedPrincipal.FindFirst("sub")?.Value;

		var displayName =
			validatedPrincipal.FindFirst("name")?.Value
			?? validatedPrincipal.FindFirst("preferred_username")?.Value
			?? subject;

		var claims = new List<Claim>
	{
		new Claim(ClaimTypes.NameIdentifier, subject!),
		new Claim(ClaimTypes.Name, displayName!),
		new Claim("IdentityProvider", "EntraExternalID")
	};

		var identity = new ClaimsIdentity(
			claims,
			"ValoraClient");

		var principal = new ClaimsPrincipal(identity);

		await HttpContext.SignInAsync(
			"ValoraClient",
			principal,
			new AuthenticationProperties
			{
				IsPersistent = false,
				AllowRefresh = true,
				ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30)
			});

		HttpContext.Session.Remove("Valora:MfaToken");
		ClearRegistration();

		return Redirect("/client/my-account");
	}
}
