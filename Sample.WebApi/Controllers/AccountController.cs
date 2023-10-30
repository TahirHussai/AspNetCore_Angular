using AutoMapper;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.IdentityModel.Tokens;
using Octokit;
using Octokit.Internal;
using SampleAngular.DTO;
using SampleAngular.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web.Http.Results;

namespace SampleAngular.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<UserPofile> userManager;
        private readonly SignInManager<UserPofile> signInManager;
        private readonly IMapper mapper;
        private readonly ILogger<AccountController> logger;
        private readonly IConfiguration configuration;
        private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;


        public AccountController(JwtSecurityTokenHandler jwtSecurityTokenHandler, IConfiguration configuration, ILogger<AccountController> logger, IMapper mapper, UserManager<UserPofile> userManager, SignInManager<UserPofile> signInManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.mapper = mapper;
            this.logger = logger;
            this.configuration = configuration;
            _jwtSecurityTokenHandler = jwtSecurityTokenHandler;
        }
        [HttpPost]
        [Route("UserLogin")]
        public async Task<ActionResult<ResponseDto>> Login(LoginDTO userDto)
        {
            if (userDto == null)
            {
                return BadRequest();
            }
            try
            {
                logger.LogInformation($"Attempt User Logn via {userDto.Email}");
                return await LoginUser(userDto);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Something went wrong in  the {nameof(Login)} with user {userDto.Email}");
                return Problem(ex.ToString());
            }
        }
        [HttpPost]
        [Route("UserRegister")]
        public async Task<IActionResult> Register(UserDto userDto)
        {
            if (userDto == null)
            {
                return BadRequest();
            }
            try
            {
                return await RegisterUser(userDto);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Something went wrong in  the {nameof(Register)} with user {userDto.Email}");

            }
            return Ok();
        }
        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenDto tokenModel)
        {

            if (tokenModel is null)
            {
                return BadRequest("Invalid client request");
            }

            string? accessToken = tokenModel.AccessToken;
            string? refreshToken = tokenModel.RefreshToken;

            var principal = GetPrincipalFromExpiredToken(accessToken);
            if (principal == null)
            {
                return BadRequest("Invalid access token or refresh token");
            }

#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
#pragma warning disable CS8602 // Dereference of a possibly null reference.
            string username = principal.Identity.Name;
#pragma warning restore CS8602 // Dereference of a possibly null reference.
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.

            var user = await userManager.FindByEmailAsync(username);

            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest("Invalid access token or refresh token");
            }

            var newAccessToken = GenerateToken(user).ToString();
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await userManager.UpdateAsync(user);

            return new ObjectResult(new
            {
                accessToken = newAccessToken,
                refreshToken = newRefreshToken
            });
        }
        [HttpGet]
        [Route("ExternalLogin")]
        public async Task<ActionResult<List<ExterLogin>>> onGeAsync()
        {
            List<ExterLogin> logins = new List<ExterLogin>();
            var obj = new ExterLogin();

            obj.RedirectUrl = "https://localhost:7206/signin-google";
            //clear the external cookie to ensure the clear login
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            var Externallogins = (await signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            obj.loginName = Externallogins[0].DisplayName;
            // obj.HandlerType= logins[0].HandlerType.ToString();
            logins.Add(obj);
            return Ok(logins);
        }
        [HttpGet]
        [Route("google-login")]
        public IActionResult GoogleLogin(string redirectUrl)
        {
            //HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            //var Externallogins =  signInManager.GetExternalAuthenticationSchemesAsync();
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("GoogleLoginCallback", "Account", new { redirectUrl = redirectUrl }),
                Items = { { "scheme", "Google" } }
            };

            return Challenge(properties, "Google");
        }

        [HttpGet("google-login-callback")]
        public async Task<IActionResult> GoogleLoginCallback(string redirectUrl)
        {
            var authenticateResult = await HttpContext.AuthenticateAsync("Google");

            if (authenticateResult.Succeeded)
            {
                var user = new UserDto();
                Guid newGuid = Guid.NewGuid();
                // Claims associated with the authenticated user
                var claims = authenticateResult.Principal.Claims;
                user.Email = authenticateResult.Principal.FindFirstValue(ClaimTypes.Email);
                user.FirstName = authenticateResult.Principal.FindFirstValue(ClaimTypes.GivenName);
                user.Lastname = authenticateResult.Principal.FindFirstValue(ClaimTypes.Surname);
                var users = await userManager.FindByEmailAsync(user.Email);
                if (users == null)
                {
                    user.Password = "M1@" + newGuid.ToString();
                    var response = await RegisterUser(user);
                }
                else
                {
                    user.Password = users.UserPassword;
                }
                //if (response.ToString()==200)
                //{

                //}
                //if (response.)
                //{

                //}
                //LoginDTO dto = new LoginDTO();
                //dto.Email = user.Email;
                //dto.Password = user.Password;
                //var ResponseModel= LoginUser(dto);
                return Redirect($"{redirectUrl}/{user.Email}/{user.Password}");
            }
            //var googleUser=  this.User.Identities.FirstOrDefault();
            //if (googleUser.IsAuthenticated)
            //{
            //    var name = googleUser.Name;
            //    var claims = googleUser.Claims;
            //    var roles = googleUser.RoleClaimType;
            //    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(googleUser));
            //}
            //var info = await signInManager.GetExternalLoginInfoAsync();
            //var props = new AuthenticationProperties();
            //props.StoreTokens(info.AuthenticationTokens);
            // Authenticate user and generate an authentication token (JWT)

            return Redirect($"{redirectUrl}/?Email={""}&&Password={""}");
        }

        [HttpGet("facebook-login")]
        public IActionResult FacebookLogin(string redirectUrl)
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("FacebookResponse", "Account", new { redirectUrl = redirectUrl.ToString() }),
                Items = { { "scheme", "Facebook" } }
            };

            return Challenge(properties, "Facebook");

        }
        [HttpGet("FacebookResponse")]
        public async Task<IActionResult> FacebookResponse(string redirectUrl)
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(FacebookDefaults.AuthenticationScheme);
            if (authenticateResult.Succeeded)
            {
                var user = new UserDto();
                Guid newGuid = Guid.NewGuid();
                // Claims associated with the authenticated user
                var claims = authenticateResult.Principal.Claims;
                user.Email = authenticateResult.Principal.FindFirstValue(ClaimTypes.Email);
                user.FirstName = authenticateResult.Principal.FindFirstValue(ClaimTypes.GivenName);
                user.Lastname = authenticateResult.Principal.FindFirstValue(ClaimTypes.Surname);
                var users = await userManager.FindByEmailAsync(user.Email);
                if (users == null)
                {
                    user.Password = "M1@" + newGuid.ToString();
                    var response = await RegisterUser(user);
                }
                else
                {
                    user.Password = users.UserPassword;
                }
                return Redirect($"{redirectUrl}/{user.Email}/{user.Password}");
            }

            // You can access user information using `authenticateResult.Principal`.

            // Add your logic for user registration or sign-in here.

            return Redirect($"{redirectUrl}/?Email={""}&&Password={""}");
        }

        [HttpGet("signin-linkedin")]
        public IActionResult LinkedInLogin(string redirectUrl)
        {
            //return Challenge(new AuthenticationProperties { RedirectUri = Url.Action("linkedinResponse", "Account", new { redirectUrl = redirectUrl }, "LinkedIn") });
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("linkedinResponse", "Account", new { redirectUrl = redirectUrl }
               ),
                Items = { { "scheme", "LinkedIn" } }
            };

            return Challenge(properties, "LinkedIn");
        }
        [HttpGet("linkedinResponse")]
        public async Task<IActionResult> LinkedInResponse(string redirectUrl)
        {
            var result = await HttpContext.AuthenticateAsync("LinkedIn");
            var user = new UserDto();
            Guid newGuid = Guid.NewGuid();

            user.FirstName = result.Principal.FindFirst("urn:linkedin:name")?.Value;
            user.Lastname = "";// result.Principal.FindFirst("urn:linkedin:lastName")?.Value;
            user.Email = result.Principal.FindFirst("urn:linkedin:email")?.Value;

            var users = await userManager.FindByEmailAsync(user.Email);
            if (users == null)
            {
                user.Password = "M1@" + newGuid.ToString();
                var response = await RegisterUser(user);
            }
            else
            {
                user.Password = users.UserPassword;
            }
            return Redirect($"{redirectUrl}/{user.Email}/{user.Password}");

        }

        [HttpGet("signin-github")]
        public IActionResult GitHubLogin(string redirectUrl)
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("GitHubCallback", "Account", new { redirectUrl = redirectUrl })

            };
            return Challenge(properties, "GitHub");
        }

        [HttpGet("github-callback")]
        public async Task<IActionResult> GitHubCallback(string redirectUrl)
        {
            var result = await HttpContext.AuthenticateAsync("GitHub");
            if (!result.Succeeded)
            {
                return RedirectToAction("Login");
            }
            var user = new UserDto();
            Guid newGuid = Guid.NewGuid();

            user.FirstName = result.Principal.FindFirst(ClaimTypes.Name)?.Value;

            user.Email = result.Principal.FindFirst("urn:github:email")?.Value;

            var users = await userManager.FindByEmailAsync(user.Email);
            if (users == null)
            {
                user.Password = "M1@" + newGuid.ToString();
                var response = await RegisterUser(user);
            }
            else
            {
                user.Password = users.UserPassword;
            }
            return Redirect($"{redirectUrl}/{user.Email}/{user.Password}");
        }
        private async Task<IActionResult> RegisterUser(UserDto userDto)
        {

            logger.LogInformation($"Attempt User Register via {userDto.Email}");
            var user = mapper.Map<UserPofile>(userDto);
            user.UserName = userDto.Email;
            user.ProfilePicture = " ";
            user.UserPassword = userDto.Password;
            var suceess = await userManager.CreateAsync(user, userDto.Password);
            if (suceess.Succeeded == false)
            {
                foreach (var item in suceess.Errors)
                {
                    ModelState.AddModelError(item.Code, item.Description);
                    return BadRequest(ModelState);
                }
            }
            await userManager.AddToRoleAsync(user, "User");
            return Ok();
        }
        private async Task<ActionResult<ResponseDto>> LoginUser(LoginDTO userDto)
        {

            var user = await userManager.FindByEmailAsync(userDto.Email);
            if (user == null)
            {
                logger.LogError($"Something went wrong with the {userDto.Email}");
                return Unauthorized(userDto);
            }
            var validatePassword = await userManager.CheckPasswordAsync(user, userDto.Password);
            if (validatePassword == false)
            {
                return Unauthorized(userDto);
            }
            var token = await GenerateToken(user);
            var refreshToken = GenerateRefreshToken();
            _ = int.TryParse(configuration["jWTSetting:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

            await userManager.UpdateAsync(user);
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenString = tokenHandler.WriteToken(token);


            // var encodedTokenString = Base64UrlEncoder.Encode(tokenString);

            var response = new ResponseDto
            {
                Email = user.Email,
                TokenString = tokenString,
                Userid = user.Id,
                RefreshToken = refreshToken,
                Expiration = token.ValidTo
            };
            return response;
        }
        private async Task<JwtSecurityToken> GenerateToken(UserPofile user)
        {
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JwtSetting:IssuerSigningKey"]));
            var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);

            var roles = await userManager.GetRolesAsync(user);
            var roleClaims = roles.Select(q => new Claim(ClaimTypes.Role, q)).ToList();

            var userClaims = await userManager.GetClaimsAsync(user);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                 new Claim(ClaimTypes.Name, user.Email),
                 new Claim("ProfileImage", user.ProfilePicture),
            }
           .Union(userClaims)
           .Union(roleClaims);

            var token = new JwtSecurityToken(
                issuer: configuration["jWTSetting:Issuer"],
                audience: configuration["jWTSetting:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToInt32(configuration["jWTSetting:Duration"])),
                signingCredentials: credentials
            );

            return token;
        }
        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["jWTSetting:IssuerSigningKey"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;

        }
    }
}
