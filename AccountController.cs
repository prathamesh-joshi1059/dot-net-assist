﻿using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using CMSAdmin.Models;
using System.Collections.Generic;

namespace CMSAdmin.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        log4net.ILog logger = log4net.LogManager.GetLogger(typeof(AccountController));
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set
            {
                _signInManager = value;
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
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
                List<string> _errors = new List<string>();
                try
                {
                    returnUrl = "/CMSAdmin/Index";
                    RBACStatus _retVal = this.Login(model, this.UserManager, this.SignInManager, out _errors);
                    switch (_retVal)
                    {
                        case RBACStatus.Success:
                            {
                                return RedirectToLocal("/CMSAdmin/Index");
                            }
                        case RBACStatus.EmailUnconfirmed:
                            {
                                //Do nothing, message will be display on login page...
                                break;
                            }
                        case RBACStatus.PhoneNumberUnconfirmed:
                            {
                                var user = UserManager.FindByName(model.UserName);
                                if (user != null)
                                {
                                    if (this.SendOTP2Phone(this.UserManager, user.Id, user.PhoneNumber))
                                        return RedirectToAction("OTP4PhoneVerification", new { UserId = user.Id, phoneNumber = user.PhoneNumber, displayError = true });
                                }
                                break;
                            }
                        case RBACStatus.RequiresVerification:
                            return RedirectToAction("SendSecurityCode", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                        case RBACStatus.LockedOut:
                            return View("Lockout");
                            //case RBACStatus.Failure:
                            //default:
                            //    ModelState.AddModelError("", "Invalid login attempt.");
                    }
                }
                catch (Exception ex)
                {
                    logger.Fatal(ex.ToString());
                    AddErrors(new IdentityResult(ex.Message));
                }

                if (_errors.Any())
                {
                    AddErrors(new IdentityResult(_errors));
                }
            }
            // If we reach this point, something failed, redisplay form displaying error message(s)...
            return View(model);
        }
        #endregion

        #region Verification
        [AllowAnonymous]
        public ActionResult OTP4PhoneVerification(int UserId, string phoneNumber, bool displayError = false)
        {
            VerifyOTPPhoneViewModel model = new VerifyOTPPhoneViewModel();
            model.UserId = UserId;
            model.PhoneNumber = phoneNumber;
            model.Provider = "Phone Code";

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
            {
                return View(model);
            }

            IEnumerable<string> _errors; 
            RBACStatus result = ExtendedMethods.VerifyOTP4Phone(model.UserId, model.PhoneNumber, model.Code, this.UserManager, this.SignInManager, out _errors);
            if (result == RBACStatus.Success)
            {
                return RedirectToAction("Index", "Home");
            }
            AddErrors(new IdentityResult(_errors));
            return View(model);
        }

        [AllowAnonymous]
        public ActionResult OTP4EmailVerification(int UserId, string email)
        {
            TOTP4EmailViewModelGet model = new TOTP4EmailViewModelGet();
            model.UserId = UserId;
            model.Email = email;
            model.Provider = "Email Code";
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult OTP4EmailVerification(TOTP4EmailViewModelPost model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            IEnumerable<string> _errors = new string[0];
            bool result = ExtendedMethods.VerifyOTP4Email(model.UserId, model.SecurityPIN, this.UserManager, this.SignInManager, out _errors);
            if (result)
            {
                return RedirectToAction("Index", "Home");
            }
            AddErrors(new IdentityResult(_errors));
            return View(model);
        }

        [AllowAnonymous]
        public ActionResult RequestEmailVerification(string Username)
        {
            var user = this.UserManager.FindByName(Username);
            if (user != null)
            {
                TOTP4EmailViewModelGet model = new TOTP4EmailViewModelGet();
                model.UserId = user.Id;
                model.Provider = "Email Code";
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
            {
                return View(model);
            }

            IEnumerable<string> _errors = new string[0];
            RBACStatus result = this.RequestAccountVerification(model.UserId, model.Email, this.UserManager, out _errors);
            if (result == RBACStatus.RequiresAccountActivation)
            {
                ViewBag.Message = string.Format("To verify your identity, please activate this account using the e-mail sent to '{0}'", model.Email);

                var user = this.UserManager.FindById(model.UserId);
                if (user != null)
                {
                    ViewBag.Username = user.UserName;
                    ViewBag.Email = model.Email;
                    return View("ConfirmEmailSent");
                }

            }
            AddErrors(new IdentityResult(_errors));
            return View(model);
        }

        #region 2FA - Send Security Code 2 Registered Device(s)
        [AllowAnonymous]
        public async Task<ActionResult> SendSecurityCode(string returnUrl, bool rememberMe)
        {
            var userId = await SignInManager.GetVerifiedUserIdAsync();
            if (userId == 0)
            {
                ViewBag.ErrorCode = "0x0001";
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendSecurityCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Generate the token and send it
            if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                ViewBag.ErrorCode = "0x0002";
                return View("Error");
            }

            //this.SendOTP2Phone            
            TempData["DeliveryMethod"] = "sent to your email account";
            if (model.SelectedProvider == ExtendedMethods.c_PhoneCode)
                TempData["DeliveryMethod"] = "texted to your phone";

            return RedirectToAction("VerifySecurityCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        [AllowAnonymous]
        public async Task<ActionResult> VerifySecurityCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                ViewBag.ErrorCode = "0x0003";
                return View("Error");
            }
            @ViewBag.DeliveryMethod = TempData["DeliveryMethod"];
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifySecurityCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent: model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }
        #endregion

        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                ViewBag.ErrorCode = "0x0004";
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in IdentityConfig
            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent: model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }
        #endregion

        #region Register
        //[AllowAnonymous]
        //public ActionResult Register()
        //{
        //    return View();
        //}

        //[HttpPost]
        //[AllowAnonymous]
        //[ValidateAntiForgeryToken]
        //public async Task<ActionResult> Register(RegisterViewModel model)
        //{
        //    if (ModelState.IsValid)
        //    {
        //        List<string> _errors = new List<string>();
        //        try
        //        {
        //            RBACStatus _retVal = this.Register(model, this.UserManager, this.SignInManager, out _errors);
        //            switch (_retVal)
        //            {
        //                case RBACStatus.Success:
        //                    {
        //                        ViewBag.Message = "Your account has been created successfully.  You can now continue and login...";
        //                        return View("Confirmation");
        //                    }
        //                case RBACStatus.RequiresAccountActivation:
        //                    {
        //                        ViewBag.Username = model.UserName;
        //                        ViewBag.Email = model.Email;
        //                        return View("ConfirmEmailSent");
        //                    }
        //                case RBACStatus.EmailVerification:
        //                    {
        //                        return RedirectToAction("RequestEmailVerification", new { Username = model.UserName });
        //                        //return RedirectToAction("TOTPEmailVerification4Registration", new { UserId = model.Id, email = model.Email });   

        //                    }
        //                case RBACStatus.PhoneVerification:
        //                    {
        //                        return RedirectToAction("OTP4PhoneVerification", new { UserId = model.Id, phoneNumber = model.Mobile });
        //                    }
        //            }
        //        }
        //        catch (Exception ex)
        //        {
        //            AddErrors(new IdentityResult(ex.Message));
        //        }

        //        if (_errors.Count() > 0)
        //        {
        //            AddErrors(new IdentityResult(_errors));
        //        }
        //    }

        //    //If we got this far, something failed, redisplay form
        //    //Errors will be displayed back to the user because we have set the ModelState object with our _errors list...
        //    return View(model);
        //}

        #endregion

        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(int userId, string code)
        {
            if (userId == 0 || code == null)
            {
                ViewBag.ErrorCode = "0x0005";
                return View("Error");
            }
            var result = await UserManager.ConfirmEmailAsync(userId, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        #region Password Management
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                //var user = await UserManager.FindByNameAsync(model.Email);
                var user = await UserManager.FindByEmailAsync(model.Email);
                if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
                return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            ViewBag.RequiredLength = ExtendedMethods.GetConfigSettingAsInt(ExtendedMethods.cKey_PasswordRequiredLength, 6);
            ViewBag.ErrorCode = "0x0006";
            return code == null ? View("Error") : View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            //var user = await UserManager.FindByNameAsync(model.Email);
            var user = await UserManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View();
        }

        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }
        #endregion

        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            var userId = await SignInManager.GetVerifiedUserIdAsync();
            if (userId == 0)
            {
                ViewBag.ErrorCode = "0x0007";
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Generate the token and send it
            if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                ViewBag.ErrorCode = "0x0008";
                return View("Error");
            }
            return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        ////
        //// POST: /Account/ExternalLogin
        //[HttpPost]
        //[AllowAnonymous]
        //[ValidateAntiForgeryToken]
        //public ActionResult ExternalLogin(string provider, string returnUrl)
        //{
        //    // Request a redirect to the external login provider
        //    return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        //}

        ////
        //// GET: /Account/ExternalLoginCallback
        //[AllowAnonymous]
        //public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        //{
        //    var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
        //    if (loginInfo == null)
        //    {
        //        return RedirectToAction("Login");
        //    }

        //    // Sign in the user with this external login provider if the user already has a login
        //    var result = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
        //    switch (result)
        //    {
        //        case SignInStatus.Success:
        //            return RedirectToLocal(returnUrl);
        //        case SignInStatus.LockedOut:
        //            return View("Lockout");
        //        case SignInStatus.RequiresVerification:
        //            return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
        //        case SignInStatus.Failure:
        //        default:
        //            // If the user does not have an account, then prompt the user to create an account
        //            ViewBag.ReturnUrl = returnUrl;
        //            ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
        //            return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
        //    }
        //}

        ////
        //// POST: /Account/ExternalLoginConfirmation
        //[HttpPost]
        //[AllowAnonymous]
        //[ValidateAntiForgeryToken]
        //public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        //{
        //    if (User.Identity.IsAuthenticated)
        //    {
        //        return RedirectToAction("Index", "Manage");
        //    }

        //    if (ModelState.IsValid)
        //    {
        //        // Get the information about the user from the external login provider
        //        var info = await AuthenticationManager.GetExternalLoginInfoAsync();
        //        if (info == null)
        //        {
        //            return View("ExternalLoginFailure");
        //        }
        //        var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
        //        var result = await UserManager.CreateAsync(user);
        //        if (result.Succeeded)
        //        {
        //            result = await UserManager.AddLoginAsync(user.Id, info.Login);
        //            if (result.Succeeded)
        //            {
        //                await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
        //                return RedirectToLocal(returnUrl);
        //            }
        //        }
        //        AddErrors(result);
        //    }

        //    ViewBag.ReturnUrl = returnUrl;
        //    return View(model);
        //}
        //
        //// GET: /Account/ExternalLoginFailure
        //[AllowAnonymous]
        //public ActionResult ExternalLoginFailure()
        //{
        //    return View();
        //}

        //
        // POST: /Account/LogOff
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
            Session.Clear();
            Session.Abandon();
            Session.RemoveAll();

            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);

            this.Response.Cache.SetExpires(DateTime.UtcNow.AddMinutes(-1));
            this.Response.Cache.SetCacheability(HttpCacheability.NoCache);
            this.Response.Cache.SetNoStore();

            return RedirectToAction("Login", "Account");
        }


        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }

            base.Dispose(disposing);
        }

        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion
    }
}