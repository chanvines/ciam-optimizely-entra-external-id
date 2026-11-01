using System.Text.Json;
using System.Text.Json.Serialization;

namespace CiamOptimizelyPortal.Services;

public class PasswordResetResponse
{
    [JsonPropertyName("continuation_token")]
    public string ContinuationToken { get; set; }

    [JsonPropertyName("challenge_type")]
    public string ChallengeType { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; }

    [JsonPropertyName("poll_interval")]
    public int? PollInterval { get; set; }

    [JsonPropertyName("error")]
    public string Error { get; set; }

    [JsonPropertyName("suberror")]
    public string SubError { get; set; }
}

public class PasswordResetService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;

    public PasswordResetService(
        HttpClient httpClient,
        IConfiguration configuration)
    {
        _httpClient = httpClient;
        _configuration = configuration;
    }

    private async Task<PasswordResetResponse> PostAsync(
        string endpoint,
        Dictionary<string, string> parameters)
    {
        var tenant =
            _configuration["EntraExternal:TenantSubdomain"];

        var clientId =
            _configuration["EntraExternal:ClientId"];

        if (string.IsNullOrWhiteSpace(tenant) ||
            string.IsNullOrWhiteSpace(clientId))
        {
            throw new InvalidOperationException(
                "Entra External ID configuration is missing.");
        }

        var url =
            $"https://{tenant}.ciamlogin.com/" +
            $"{tenant}.onmicrosoft.com/resetpassword/v1.0/" +
            endpoint;

        parameters["client_id"] = clientId;

        using var content =
            new FormUrlEncodedContent(parameters);

        using var response =
            await _httpClient.PostAsync(url, content);

        var json =
            await response.Content.ReadAsStringAsync();

        return JsonSerializer.Deserialize<PasswordResetResponse>(
            json)
            ?? new PasswordResetResponse
            {
                Error = "empty_response"
            };
    }

    public Task<PasswordResetResponse> StartAsync(
        string email)
    {
        return PostAsync(
            "start",
            new Dictionary<string, string>
            {
                ["username"] = email,
                ["challenge_type"] = "oob redirect"
            });
    }

    public Task<PasswordResetResponse> ChallengeAsync(
        string continuationToken)
    {
        return PostAsync(
            "challenge",
            new Dictionary<string, string>
            {
                ["continuation_token"] = continuationToken,
                ["challenge_type"] = "oob redirect"
            });
    }

    public Task<PasswordResetResponse> ContinueAsync(
        string continuationToken,
        string code)
    {
        return PostAsync(
            "continue",
            new Dictionary<string, string>
            {
                ["continuation_token"] = continuationToken,
                ["grant_type"] = "oob",
                ["oob"] = code
            });
    }

    public Task<PasswordResetResponse> SubmitAsync(
        string continuationToken,
        string newPassword)
    {
        return PostAsync(
            "submit",
            new Dictionary<string, string>
            {
                ["continuation_token"] = continuationToken,
                ["new_password"] = newPassword
            });
    }

    public Task<PasswordResetResponse> PollCompletionAsync(
        string continuationToken)
    {
        return PostAsync(
            "poll_completion",
            new Dictionary<string, string>
            {
                ["continuation_token"] = continuationToken
            });
    }
}
