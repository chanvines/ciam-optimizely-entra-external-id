using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;

namespace CiamOptimizelyPortal.Controllers;

public class ClientAccountController : Controller
{
    [HttpGet("/client/my-account")]
    [Authorize(AuthenticationSchemes = "ValoraClient")]
    public IActionResult MyAccount()
    {
        return View();
    }

    [HttpPost("/client/logout")]
    [Authorize(AuthenticationSchemes = "ValoraClient")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync("ValoraClient");

        return Redirect("/client/login");
    }
}
