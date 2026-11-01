using System.Text.Json.Serialization;

namespace CiamOptimizelyPortal.Services;

public class NativeAuthResponse
{
    [JsonPropertyName("continuation_token")]
    public string ContinuationToken { get; set; }

    [JsonPropertyName("challenge_type")]
    public string ChallengeType { get; set; }

    [JsonPropertyName("error")]
    public string Error { get; set; }

    [JsonPropertyName("error_description")]
    public string ErrorDescription { get; set; }
}
