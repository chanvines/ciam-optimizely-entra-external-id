using System.Net.Http;
using System.Text.Json;

namespace CiamOptimizelyPortal.Services;

public partial class NativeAuthService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<NativeAuthService> _logger;

    public NativeAuthService(
        HttpClient httpClient,
        IConfiguration configuration,
        ILogger<NativeAuthService> logger)
    {
        _httpClient = httpClient;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<NativeAuthResponse> StartSignInAsync(string email)
    {
        var tenant = _configuration["EntraExternal:TenantSubdomain"];
        var clientId = _configuration["EntraExternal:ClientId"];

        if (string.IsNullOrWhiteSpace(tenant) ||
            string.IsNullOrWhiteSpace(clientId))
        {
            throw new InvalidOperationException(
                "La configuration Entra External ID est manquante.");
        }

        var url =
            $"https://{tenant}.ciamlogin.com/" +
            $"{tenant}.onmicrosoft.com/oauth2/v2.0/initiate";

        var parameters = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["challenge_type"] = "password redirect",
            ["username"] = email,
            ["capabilities"] = "registration_required mfa_required"
        };

        using var content = new FormUrlEncodedContent(parameters);

        using var response = await _httpClient.PostAsync(url, content);

        var responseBody = await response.Content.ReadAsStringAsync();
        LogOutcome("initiate", response, responseBody);

        var result = JsonSerializer.Deserialize<NativeAuthResponse>(
            responseBody
        );

        return result ?? new NativeAuthResponse
        {
            Error = "empty_response"
        };
    }
    public async Task<NativeAuthResponse> ChallengeAsync(
    string continuationToken)
    {
        var tenant = _configuration["EntraExternal:TenantSubdomain"];
        var clientId = _configuration["EntraExternal:ClientId"];

        var url =
            $"https://{tenant}.ciamlogin.com/" +
            $"{tenant}.onmicrosoft.com/oauth2/v2.0/challenge";

        var parameters = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["challenge_type"] = "password redirect",
            ["continuation_token"] = continuationToken
        };

        using var content = new FormUrlEncodedContent(parameters);

        using var response =
            await _httpClient.PostAsync(url, content);

        var responseBody =
            await response.Content.ReadAsStringAsync();
        LogOutcome("challenge", response, responseBody);

        return JsonSerializer.Deserialize<NativeAuthResponse>(
            responseBody
        ) ?? new NativeAuthResponse
        {
            Error = "empty_response"
        };
    }

    public async Task<NativeTokenResponse> SubmitPasswordAsync(
    string continuationToken,
    string password)
    {
        var tenant =
            _configuration["EntraExternal:TenantSubdomain"];

        var clientId =
            _configuration["EntraExternal:ClientId"];

        var url =
            $"https://{tenant}.ciamlogin.com/" +
            $"{tenant}.onmicrosoft.com/oauth2/v2.0/token";

        var parameters = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["continuation_token"] = continuationToken,
            ["grant_type"] = "password",
            ["password"] = password,
            ["scope"] = "openid profile"
        };

        using var content =
            new FormUrlEncodedContent(parameters);

        using var response =
            await _httpClient.PostAsync(url, content);

        var responseBody =
            await response.Content.ReadAsStringAsync();
        LogOutcome("token", response, responseBody);

        var result =
            JsonSerializer.Deserialize<NativeTokenResponse>(
                responseBody);

        return result ?? new NativeTokenResponse
        {
            Error = "empty_response"
        };
    }

    public async Task<NativeTokenResponse> TestSignInAsync(
    string email,
    string password)
    {
        // 1. Initiate
        var initiation = await StartSignInAsync(email);

        if (string.IsNullOrEmpty(
            initiation.ContinuationToken))
        {
            return new NativeTokenResponse
            {
                Error = initiation.Error ?? "initiate_failed"
            };
        }

        // 2. Challenge
        var challenge = await ChallengeAsync(
            initiation.ContinuationToken);

        if (challenge.ChallengeType != "password" ||
            string.IsNullOrEmpty(challenge.ContinuationToken))
        {
            return new NativeTokenResponse
            {
                ChallengeType = challenge.ChallengeType,
                ContinuationToken = challenge.ContinuationToken,
                Error = challenge.Error ?? "unsupported_challenge"
            };
        }

        // 3. Submit password
        return await SubmitPasswordAsync(
            challenge.ContinuationToken,
            password);
    }

    private void LogOutcome(string step, HttpResponseMessage response, string json)
    {
        if (response.IsSuccessStatusCode) return;

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        string Read(string key) => root.TryGetProperty(key, out var value) &&
            value.ValueKind == JsonValueKind.String ? value.GetString() : null;

        // Only predefined categories and a numeric AADSTS code may enter logs.
        // Never log the response body, credentials, identifiers or tokens.
        var error = Read("error") switch
        {
            "invalid_grant" => "invalid_grant",
            "invalid_request" => "invalid_request",
            "invalid_client" => "invalid_client",
            "unauthorized_client" => "unauthorized_client",
            "unsupported_grant_type" => "unsupported_grant_type",
            "invalid_scope" => "invalid_scope",
            "expired_token" => "expired_token",
            _ => "other"
        };
        var suberror = Read("suberror") switch
        {
            "mfa_required" => "mfa_required",
            "registration_required" => "registration_required",
            "invalid_credentials" => "invalid_credentials",
            "user_not_found" => "user_not_found",
            "password_reset_required" => "password_reset_required",
            "invalid_oob_value" => "invalid_oob_value",
            _ => "other_or_absent"
        };
        var match = System.Text.RegularExpressions.Regex.Match(
            Read("error_description") ?? "", @"\bAADSTS[0-9]{4,12}\b");
        _logger.LogWarning(
            "Entra native auth: step={Step}, HTTP={Status}, error={Error}, suberror={Suberror}, code={Code}",
            step, (int)response.StatusCode, error, suberror,
            match.Success ? match.Value : "absent");
    }
}
