using System.Security.Claims;

namespace CiamOptimizelyPortal.Services;

public interface ITokenValidationService
{
    Task<ClaimsPrincipal> ValidateAsync(string idToken);
}
