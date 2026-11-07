using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace CiamOptimizelyPortal.Services;

public sealed class SalesforceContacts(HttpClient http, IConfiguration configuration)
{
    private const string Fields = "Id, Email, FirstName, LastName, ContactStatus__c, EntraObjectID__c, LastModifiedDate";
    private readonly IConfigurationSection settings = configuration.GetSection("Salesforce");

    public bool IsEnabled => settings.Exists();

    public bool IsConfigured =>
        Uri.TryCreate(settings["LoginUrl"], UriKind.Absolute, out var login) && login.Scheme == "https" &&
        !string.IsNullOrWhiteSpace(settings["ClientId"]) && !string.IsNullOrWhiteSpace(settings["ClientSecret"]) &&
        Regex.IsMatch(settings["ApiVersion"] ?? "", @"\Av[0-9]+\.[0-9]+\z");

    public Task<SalesforceContact> FindByEmailAsync(string email, CancellationToken cancellationToken) =>
        FindUniqueAsync("Email", email, cancellationToken);

    public Task<SalesforceContact> FindByObjectIdAsync(Guid objectId, CancellationToken cancellationToken) =>
        FindUniqueAsync("EntraObjectID__c", objectId.ToString("D"), cancellationToken);

    public async Task<bool> LinkAsync(SalesforceContact contact, Guid objectId, CancellationToken cancellationToken)
    {
        if (!Regex.IsMatch(contact.Id ?? "", @"\A[a-zA-Z0-9]{15}([a-zA-Z0-9]{3})?\z") ||
            !DateTimeOffset.TryParse(contact.LastModifiedDate, CultureInfo.InvariantCulture, DateTimeStyles.None, out var modified))
            return false;

        using var request = await CreateRequestAsync(HttpMethod.Patch, $"sobjects/Contact/{contact.Id}", cancellationToken);
        request.Headers.IfUnmodifiedSince = modified;
        request.Content = JsonContent.Create(new Dictionary<string, string>
        {
            ["EntraObjectID__c"] = objectId.ToString("D")
        });
        using var response = await http.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.PreconditionFailed)
            return false;

        response.EnsureSuccessStatusCode();
        return true;
    }

    private async Task<SalesforceContact> FindUniqueAsync(string field, string value, CancellationToken cancellationToken)
    {
        // Escape a SOQL string literal before URL encoding the complete query.
        var literal = value.Replace("\\", "\\\\").Replace("'", "\\'");
        var query = $"SELECT {Fields} FROM Contact WHERE {field} = '{literal}' LIMIT 2";
        using var request = await CreateRequestAsync(HttpMethod.Get, $"query?q={Uri.EscapeDataString(query)}", cancellationToken);
        using var response = await http.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<QueryResult>(cancellationToken);
        return result is { Done: true, TotalSize: 1, Records.Length: 1 } ? result.Records[0] : null;
    }

    private async Task<HttpRequestMessage> CreateRequestAsync(HttpMethod method, string path, CancellationToken cancellationToken)
    {
        if (!IsConfigured)
            throw new HttpRequestException("Salesforce integration is unavailable.");

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = settings["ClientId"],
            ["client_secret"] = settings["ClientSecret"]
        });
        var loginUrl = settings["LoginUrl"].TrimEnd('/');
        using var response = await http.PostAsync($"{loginUrl}/services/oauth2/token", content, cancellationToken);
        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<OAuthToken>(cancellationToken);
        if (string.IsNullOrWhiteSpace(token?.AccessToken) ||
            !Uri.TryCreate(token.InstanceUrl, UriKind.Absolute, out var instance) || instance.Scheme != "https")
            throw new HttpRequestException("Salesforce returned an invalid OAuth response.");

        var request = new HttpRequestMessage(method,
            $"{instance.GetLeftPart(UriPartial.Authority)}/services/data/{settings["ApiVersion"]}/{path}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
        return request;
    }

    private sealed record QueryResult(bool Done, int TotalSize, SalesforceContact[] Records);
    private sealed record OAuthToken(
        [property: JsonPropertyName("access_token")] string AccessToken,
        [property: JsonPropertyName("instance_url")] string InstanceUrl);
}

public sealed record SalesforceContact(
    string Id, string Email, string FirstName, string LastName,
    [property: JsonPropertyName("ContactStatus__c")] string Status,
    [property: JsonPropertyName("EntraObjectID__c")] string EntraObjectId,
    string LastModifiedDate)
{
    public bool IsActive => Status == "Active";
    public string DisplayName => $"{LastName?.Trim()} {FirstName?.Trim()}".Trim();
}
