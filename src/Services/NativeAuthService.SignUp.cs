using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CiamOptimizelyPortal.Services;

public partial class NativeAuthService
{
    private const string SignUpChallengeTypes = "oob password redirect";

    public Task<SignUpResponse> StartSignUpAsync(string email) =>
        PostSignUpAsync("start", new()
        {
            ["username"] = email,
            ["challenge_type"] = SignUpChallengeTypes,
            ["capabilities"] = "registration_required mfa_required"
        });

    public Task<SignUpResponse> RequestSignUpChallengeAsync(string continuationToken) =>
        PostSignUpAsync("challenge", new()
        {
            ["continuation_token"] = continuationToken,
            ["challenge_type"] = SignUpChallengeTypes
        });

    public Task<SignUpResponse> VerifySignUpCodeAsync(string continuationToken, string code) =>
        PostSignUpAsync("continue", new()
        {
            ["continuation_token"] = continuationToken,
            ["grant_type"] = "oob",
            ["oob"] = code
        });

    public Task<SignUpResponse> SubmitSignUpPasswordAsync(string token, string password) =>
        PostSignUpAsync("continue", new()
        {
            ["continuation_token"] = token,
            ["grant_type"] = "password",
            ["password"] = password
        });

    public Task<SignUpResponse> SubmitSignUpAttributesAsync(string token, SalesforceContact contact) =>
        PostSignUpAsync("continue", new()
        {
            ["continuation_token"] = token,
            ["grant_type"] = "attributes",
            ["attributes"] = JsonSerializer.Serialize(new
            {
                givenName = contact.FirstName?.Trim(),
                surname = contact.LastName?.Trim(),
                displayName = contact.DisplayName
            })
        });

    private async Task<SignUpResponse> PostSignUpAsync(string step, Dictionary<string, string> parameters)
    {
        var tenant = _configuration["EntraExternal:TenantSubdomain"];
        var clientId = _configuration["EntraExternal:ClientId"];
        if (string.IsNullOrWhiteSpace(tenant) || string.IsNullOrWhiteSpace(clientId))
            throw new InvalidOperationException("Missing Entra External ID configuration.");

        parameters["client_id"] = clientId;
        using var content = new FormUrlEncodedContent(parameters);
        using var response = await _httpClient.PostAsync(
            $"https://{tenant}.ciamlogin.com/{tenant}.onmicrosoft.com/signup/v1.0/{step}", content);
        var body = await response.Content.ReadAsStringAsync();
        LogOutcome($"signup/{step}", response, body);
        var result = JsonSerializer.Deserialize<SignUpResponse>(body) ?? new SignUpResponse();
        if (!response.IsSuccessStatusCode &&
            (response.StatusCode != System.Net.HttpStatusCode.BadRequest || string.IsNullOrWhiteSpace(result.Error)))
            result.Error = "http_error";

        return result;
    }
}

public sealed class SignUpResponse : NativeAuthResponse
{
    [JsonPropertyName("challenge_channel")]
    public string ChallengeChannel { get; set; }

    public bool CanContinue => string.IsNullOrWhiteSpace(Error) && !string.IsNullOrWhiteSpace(ContinuationToken);
}
