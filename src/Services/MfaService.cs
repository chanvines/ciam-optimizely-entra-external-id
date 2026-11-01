using System.Text.Json;
using System.Text.Json.Serialization;

namespace CiamOptimizelyPortal.Services;

public class MfaMethod
{
    [JsonPropertyName("id")]
    public string Id { get; set; }

    [JsonPropertyName("challenge_type")]
    public string ChallengeType { get; set; }

    [JsonPropertyName("challenge_channel")]
    public string ChallengeChannel { get; set; }

    [JsonPropertyName("login_hint")]
    public string LoginHint { get; set; }
}

public class MfaMethodsResponse
{
    [JsonPropertyName("continuation_token")]
    public string ContinuationToken { get; set; }

    [JsonPropertyName("methods")]
    public List<MfaMethod> Methods { get; set; } = new();

    [JsonPropertyName("error")]
    public string Error { get; set; }
}

public class MfaService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;

    public MfaService(
        HttpClient httpClient,
        IConfiguration configuration)
    {
        _httpClient = httpClient;
        _configuration = configuration;
    }

    private string GetEndpoint(string path)
    {
        var tenant =
            _configuration["EntraExternal:TenantSubdomain"];

        if (string.IsNullOrWhiteSpace(tenant))
            throw new InvalidOperationException(
                "TenantSubdomain is missing.");

        return
            $"https://{tenant}.ciamlogin.com/" +
            $"{tenant}.onmicrosoft.com/{path}";
    }

    private async Task<T> PostAsync<T>(
        string path,
        Dictionary<string, string> parameters)
    {
        var clientId =
            _configuration["EntraExternal:ClientId"];

        if (string.IsNullOrWhiteSpace(clientId))
            throw new InvalidOperationException(
                "ClientId is missing.");

        parameters["client_id"] = clientId;

        using var content =
            new FormUrlEncodedContent(parameters);

        using var response = await _httpClient.PostAsync(
            GetEndpoint(path), content);

        var json =
            await response.Content.ReadAsStringAsync();

        return JsonSerializer.Deserialize<T>(json)
            ?? throw new InvalidOperationException(
                "Empty Entra response.");
    }

    public Task<MfaMethodsResponse> GetMethodsAsync(
        string continuationToken)
    {
        return PostAsync<MfaMethodsResponse>(
            "oauth2/v2.0/introspect",
            new Dictionary<string, string>
            {
                ["continuation_token"] = continuationToken
            });
    }

    public Task<NativeAuthResponse> SendChallengeAsync(
        string continuationToken,
        string methodId)
    {
        return PostAsync<NativeAuthResponse>(
            "oauth2/v2.0/challenge",
            new Dictionary<string, string>
            {
                ["continuation_token"] = continuationToken,
                ["id"] = methodId,
                ["challenge_type"] = "oob redirect"
            });
    }

    public Task<NativeTokenResponse> VerifyCodeAsync(
        string continuationToken,
        string code)
    {
        return PostAsync<NativeTokenResponse>(
            "oauth2/v2.0/token",
            new Dictionary<string, string>
            {
                ["continuation_token"] = continuationToken,
                ["grant_type"] = "mfa_oob",
                ["oob"] = code,
                ["scope"] = "openid profile"
            });
    }
}
