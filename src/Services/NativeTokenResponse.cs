using System.Text.Json.Serialization;

namespace CiamOptimizelyPortal.Services;

public class NativeTokenResponse
{
    [JsonPropertyName("id_token")]
    public string IdToken { get; set; }

    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }

    [JsonPropertyName("continuation_token")]
    public string ContinuationToken { get; set; }

    [JsonPropertyName("challenge_type")]
    public string ChallengeType { get; set; }

    [JsonPropertyName("error")]
    public string Error { get; set; }

    [JsonPropertyName("error_description")]
    public string ErrorDescription { get; set; }

    [JsonIgnore]
    public bool HasIdToken =>
        !string.IsNullOrWhiteSpace(IdToken);

    [JsonIgnore]
    public bool RequiresAdditionalStep =>
        !HasIdToken &&
        !string.IsNullOrWhiteSpace(ContinuationToken);

    [JsonPropertyName("suberror")]
    public string SubError { get; set; }

    [JsonPropertyName("redirect_uri")]
    public string RedirectUri { get; set; }
}
