csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using CMSAdmin.Models;

namespace CMSAdmin.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly log4net.ILog logger = log4net.LogManager.GetLogger(typeof(AccountController));
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get => _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            private set => _signInManager = value;
        }

        public ApplicationUserManager UserManager
        {
            get => _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            private set => _userManager = value;
        }

        #region Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                List<string> errors = new List<string>();
                try
                {
                    returnUrl = "/CMSAdmin/Index";
                    RBACStatus status = Login(model, UserManager, SignInManager, out errors);

                    switch (status)
                    {
                        case RBACStatus.Success:
                            return RedirectToLocal(returnUrl);
                        case RBACStatus.EmailUnconfirmed:
                            break;
                        case RBACStatus.PhoneNumberUnconfirmed:
                            var user = UserManager.FindByName(model.UserName);
                            if (user != null && SendOTP2Phone(UserManager, user.Id, user.PhoneNumber))
                                return RedirectToAction("OTP4PhoneVerification", new { UserId = user.Id, phoneNumber = user.PhoneNumber, displayError = true });
                            break;
                        case RBACStatus.RequiresVerification:
                            return RedirectToAction("SendSecurityCode", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                        case RBACStatus.LockedOut:
                            return View("Lockout");
                    }
                }
                catch (Exception ex)
                {
                    logger.Fatal(ex.ToString());
                    AddErrors(new IdentityResult(ex.Message));
                }

                if (errors.Any())
                {
                    AddErrors(new IdentityResult(errors));
                }
            }

            return View(model);
        }
        #endregion

        #region Verification
        [AllowAnonymous]
        public ActionResult OTP4PhoneVerification(int UserId, string phoneNumber, bool displayError = false)
        {
            var model = new VerifyOTPPhoneViewModel
            {
                UserId = UserId,
                PhoneNumber = phoneNumber,
                Provider = "Phone Code"
            };

            if (displayError)
                AddErrors(new IdentityResult(string.Format(ExtendedMethods.c_AccountPhoneNumberUnconfirmed, phoneNumber)));

            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult OTP4PhoneVerification(VerifyOTPPhoneViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            IEnumerable<string> errors;
            RBACStatus result = ExtendedMethods.VerifyOTP4Phone(model.UserId, model.PhoneNumber, model.Code, UserManager, SignInManager, out errors);
            if (result == RBACStatus.Success)
                return RedirectToAction("Index", "Home");

            AddErrors(new IdentityResult(errors));
            return View(model);
        }

        [AllowAnonymous]
        public ActionResult OTP4EmailVerification(int UserId, string email)
        {
            var model = new TOTP4EmailViewModelGet
            {
                UserId = UserId,
                Email = email,
                Provider = "Email Code"
            };
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult OTP4EmailVerification(TOTP4EmailViewModelPost model)
        {
            if (!ModelState.IsValid)
                return View(model);

            IEnumerable<string> errors;
            bool result = ExtendedMethods.VerifyOTP4Email(model.UserId, model.SecurityPIN, UserManager, SignInManager, out errors);
            if (result)
                return RedirectToAction("Index", "Home");

            AddErrors(new IdentityResult(errors));
            return View(model);
        }

        [AllowAnonymous]
        public ActionResult RequestEmailVerification(string Username)
        {
            var user = UserManager.FindByName(Username);
            if (user != null)
            {
                var model = new TOTP4EmailViewModelGet
                {
                    UserId = user.Id,
                    Provider = "Email Code"
                };
                return View(model);
            }
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult RequestEmailVerification(TOTP4EmailViewModelGet model)
        {
            if (!ModelState.IsValid)
                return View(model);

            IEnumerable<string> errors;
            RBACStatus result = RequestAccountVerification(model.UserId, model.Email, UserManager, out errors);
            if (result == RBACStatus.RequiresAccountActivation)
            {
                ViewBag.Message = string.Format("To verify your identity, please activate this account using the e-mail sent to '{0}'", model.Email);
                var user = UserManager.FindById(model.UserId);
                if (user != null)
                {
                    ViewBag.Username = user.UserName;
                    ViewBag.Email = model.Email;
                    return View("ConfirmEmailSent");
                }
            }

            AddErrors(new IdentityResult(errors));
            return View(model);
        }
        
        // Remaining methods and regions...
        
        #endregion

        public ActionResult Logout()
        {
            if (User.Identity.IsAuthenticated)
            {
                AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                return RedirectToAction("Login", "Account");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            Response.Cache.SetExpires(DateTime.UtcNow.AddMinutes(-1));
            Response.Cache.SetCacheability(HttpCacheability.NoCache);
            Response.Cache.SetNoStore();
            return RedirectToAction("Login", "Account");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _userManager?.Dispose();
                _signInManager?.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Helpers
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager => HttpContext.GetOwinContext().Authentication;

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
                ModelState.AddModelError("", error);
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            return Url.IsLocalUrl(returnUrl) ? Redirect(returnUrl) : RedirectToAction("Index", "Home");
        }
        #endregion
    }
}