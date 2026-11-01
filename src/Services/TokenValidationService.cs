using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace CiamOptimizelyPortal.Services;

public class TokenValidationService
{
    private readonly IConfiguration _configuration;

    private readonly ConfigurationManager<OpenIdConnectConfiguration>
        _configurationManager;

    public TokenValidationService(IConfiguration configuration)
    {
        _configuration = configuration;

        var subdomain =
            configuration["EntraExternal:TenantSubdomain"];

        var tenantId =
            configuration["EntraExternal:TenantId"];

        if (string.IsNullOrWhiteSpace(subdomain) ||
            !Guid.TryParse(tenantId, out _))
        {
            throw new InvalidOperationException(
                "Invalid External ID tenant configuration.");
        }

        var metadataAddress =
            $"https://{subdomain}.ciamlogin.com/" +
            $"{tenantId}/v2.0/.well-known/openid-configuration";

        _configurationManager =
            new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever
                {
                    RequireHttps = true
                });
    }

    public async Task<ClaimsPrincipal> ValidateAsync(
        string idToken)
    {
        if (string.IsNullOrWhiteSpace(idToken))
            throw new SecurityTokenException(
                "Missing ID token.");

        var oidcConfiguration =
            await _configurationManager.GetConfigurationAsync(
                CancellationToken.None);

        var clientId =
            _configuration["EntraExternal:ClientId"];

        var tenantId =
            _configuration["EntraExternal:TenantId"];

        var parameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = oidcConfiguration.SigningKeys,

            ValidateIssuer = true,
            ValidIssuer = oidcConfiguration.Issuer,

            ValidateAudience = true,
            ValidAudience = clientId,

            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,

            ClockSkew = TimeSpan.FromMinutes(2)
        };

        var handler = new JwtSecurityTokenHandler
        {
            MapInboundClaims = false
        };

        var principal = handler.ValidateToken(
            idToken,
            parameters,
            out _);

        var tokenTenantId =
            principal.FindFirst("tid")?.Value;

        if (!string.Equals(
            tokenTenantId,
            tenantId,
            StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityTokenException(
                "Unexpected tenant.");
        }

        var subject =
            principal.FindFirst("sub")?.Value;

        if (string.IsNullOrWhiteSpace(subject))
        {
            throw new SecurityTokenException(
                "Missing subject.");
        }

        return principal;
    }
}
