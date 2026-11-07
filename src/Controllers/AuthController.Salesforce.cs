using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using CiamOptimizelyPortal.Services;
using Microsoft.AspNetCore.DataProtection;

namespace CiamOptimizelyPortal.Controllers;

public partial class AuthController
{
    private async Task<SalesforceContact> ResolveClientContactAsync(ClaimsPrincipal principal, bool mfaVerified)
    {
        if (!Guid.TryParse(principal.FindFirst("oid")?.Value, out var objectId))
            return null;

        var cancellationToken = HttpContext.RequestAborted;
        try
        {
            var pending = ReadPendingLink();
            if (pending != null && principal.Claims.Any(claim =>
                (claim.Type is "email" or "emails") &&
                string.Equals(claim.Value, pending.Email, StringComparison.OrdinalIgnoreCase)))
            {
                if (!mfaVerified)
                    return null;

                var contact = await _salesforceContacts.FindByEmailAsync(pending.Email, cancellationToken);
                if (contact is not { IsActive: true } || contact.Id != pending.ContactId ||
                    !string.Equals(contact.Email, pending.Email, StringComparison.OrdinalIgnoreCase))
                    return null;

                if (string.IsNullOrWhiteSpace(contact.EntraObjectId))
                {
                    if (!await _salesforceContacts.LinkAsync(contact, objectId, cancellationToken))
                        return null;
                }
                else if (!Guid.TryParse(contact.EntraObjectId, out var linkedId) || linkedId != objectId)
                {
                    return null;
                }

                Response.Cookies.Delete(PendingLinkCookie, PendingLinkCookieOptions());
                return contact;
            }

            var linked = await _salesforceContacts.FindByObjectIdAsync(objectId, cancellationToken);
            return linked is { IsActive: true } ? linked : null;
        }
        catch (Exception ex) when (IsRegistrationTransportError(ex) || ex is NotSupportedException)
        {
            // Leave any pending link available for the next sign-in attempt.
            return null;
        }
    }

    private PendingLink ReadPendingLink()
    {
        if (!Request.Cookies.TryGetValue(PendingLinkCookie, out var value))
            return null;

        try
        {
            return JsonSerializer.Deserialize<PendingLink>(_pendingLinkProtector.Unprotect(value));
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        {
            return null;
        }
    }
}
