using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Encodings.Web;
using TFA.JwtFeatures;
using TFA.Models;

namespace TFA.Controllers
{
    [Route("api/[controller]")]
    //[Authorize]
    [EnableCors("two_factor_auth_cors")]
    [ApiController]
    public class TFAController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;

        // for QR code
        private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

        private readonly UrlEncoder _urlEncoder;

        private readonly JwtHandler _jwtHandler;
        public TFAController(UserManager<IdentityUser> userManager, UrlEncoder urlEncoder, JwtHandler jwtHandler)
        {
            _userManager = userManager;
            _urlEncoder = urlEncoder;
            _jwtHandler = jwtHandler;
        }

        private string GenerateQrCode(string email, string unformattedKey)
        {
            return string.Format(
            AuthenticatorUriFormat,
                _urlEncoder.Encode("Code Maze Two-Factor Auth"),
                _urlEncoder.Encode(email),
                unformattedKey);
        }


        [HttpGet("tfa-setup")]
        public async Task<IActionResult> GetTfaSetup(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
        
            if (user == null)
                return BadRequest("User does not exist");

            var isTfaEnabled = await _userManager.GetTwoFactorEnabledAsync(user);

            var authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (authenticatorKey == null)
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }
            var formattedKey = GenerateQrCode(username, authenticatorKey);

            return Ok(new TfaSetupDto
            { IsTfaEnabled = isTfaEnabled, AuthenticatorKey = authenticatorKey, FormattedKey = formattedKey });
        }

        [HttpPost("tfa-setup")]
        public async Task<IActionResult> PostTfaSetup([FromBody] TfaSetupDto tfaModel)
        {
            var user = await _userManager.FindByNameAsync(tfaModel.username);
            var isValidCode = await _userManager
                .VerifyTwoFactorTokenAsync(user,
                  _userManager.Options.Tokens.AuthenticatorTokenProvider,
                  tfaModel.Code);

            if (isValidCode)
            {
                await _userManager.SetTwoFactorEnabledAsync(user, true);
                return Ok(new TfaSetupDto { IsTfaEnabled = true });
            }
            else
            {
                return BadRequest("Invalid code");
            }
        }

        [HttpDelete("tfa-setup")]
        public async Task<IActionResult> DeleteTfaSetup(string username)
        {
            var user = await _userManager.FindByNameAsync(username);

            if (user == null)
            {
                return BadRequest("User does not exist");
            }
            else
            {
                await _userManager.SetTwoFactorEnabledAsync(user, false);
                return Ok(new TfaSetupDto { IsTfaEnabled = false });
            }
        }

        
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserForAuthenticationDto userForAuthentication)
        {
            // check authen
            var user = await _userManager.FindByNameAsync(userForAuthentication.Username);
            
            if (user == null
                || !await _userManager.CheckPasswordAsync(user, userForAuthentication.Password))
                return Unauthorized(new AuthResponseDto { ErrorMessage = "Invalid Authentication" });

            var isTfaEnabled = await _userManager.GetTwoFactorEnabledAsync(user);

            if (!isTfaEnabled)
            {
                var signingCredentials = _jwtHandler.GetSigningCredentials();
                var claims = _jwtHandler.GetClaims(user);
                var tokenOptions = _jwtHandler.GenerateTokenOptions(signingCredentials, claims);
                // tao token
                var token = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

                return Ok(new AuthResponseDto { IsAuthSuccessful = true, IsTfaEnabled = false, Token = token });
            }

            return Ok(new AuthResponseDto { IsAuthSuccessful = true, IsTfaEnabled = true });
        }

        [HttpPost("login-tfa")]
        public async Task<IActionResult> LoginTfa([FromBody] TfaSetupDto tfaDto)
        {
            var user = await _userManager.FindByNameAsync(tfaDto.username);

            if (user == null)
                return Unauthorized(new AuthResponseDto { ErrorMessage = "Invalid Authentication" });

            var validVerification =
              await _userManager.VerifyTwoFactorTokenAsync(
                 user, _userManager.Options.Tokens.AuthenticatorTokenProvider, tfaDto.Code);
            if (!validVerification)
                return BadRequest("Invalid Token Verification");

            var signingCredentials = _jwtHandler.GetSigningCredentials();
            var claims = _jwtHandler.GetClaims(user);
            var tokenOptions = _jwtHandler.GenerateTokenOptions(signingCredentials, claims);
            var token = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

            return Ok(new AuthResponseDto { IsAuthSuccessful = true, IsTfaEnabled = true, Token = token });
        }
        

        [HttpPost("add-user")]
        public async Task<IActionResult> AddUser([FromBody] RegisterUser registerUser)
        {
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if(userExist != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response{ Status = "Error", Message = "User already exists!" });
            }
            IdentityUser user = new IdentityUser()
            {
                UserName = registerUser.UserName,
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString()
        };
            var result = await _userManager.CreateAsync(user, registerUser.Password);
            if(result.Succeeded) 
            {
                return StatusCode(StatusCodes.Status201Created,
                    new Response { Status = "Success", Message = "User Created Successfully" });
            }
            else
            {
                return StatusCode(StatusCodes.Status201Created,
                    new Response { Status = "Error", Message = "User Failed to Create" });
            }
        }
    }
}
/*
 tk cho username: huy   
 pass: Nguyenqhuy0002@
 */