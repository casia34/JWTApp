using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TokenSicurezza.Modells;
using TokenSicurezza.Models;
using TokenSicurezza.Services;

namespace TokenSicurezza.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserDbContext _userContext;
        private readonly ITokenService _tokenService;


        public AuthController(UserDbContext userContext, ITokenService tokenService)
        {
            _userContext = userContext ?? throw new ArgumentNullException(nameof(userContext));
            _tokenService = tokenService ?? throw new ArgumentNullException(nameof(tokenService));
        }

        [HttpPost, Route("login")]
        public IActionResult Login([FromBody] LoginModel loginModel)
        {
            if (loginModel is null)
            {
                return BadRequest("Invalid client request");
            }
            //if (user is null)
            //{

            //    return Unauthorized();
            //}

            var user = _userContext.LoginModels.FirstOrDefault(u => (u.UserName == loginModel.UserName));


            if (user.UserName == loginModel.UserName && user.Password == loginModel.Password)
            {

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, loginModel.UserName),
                    new Claim(ClaimTypes.Role, "Manager")
                };
                var accessToken = _tokenService.GenerateAccessToken(claims);
                var refreshToken = _tokenService.GenerateRefreshToken();

                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);

                _userContext.SaveChanges();

                return Ok(new AuthenticatedResponse
                {
                    Token = accessToken,
                    RefreshToken = refreshToken
                });
            }
            else
            {
                return Unauthorized();
            }

           

        }
    }
}
