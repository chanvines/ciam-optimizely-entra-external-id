using System.Net.Http;
using System.Text.Json;

namespace CiamOptimizelyPortal.Services;

public class NativeAuthService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;

    public NativeAuthService(
        HttpClient httpClient,
        IConfiguration configuration)
    {
        _httpClient = httpClient;
        _configuration = configuration;
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
}
