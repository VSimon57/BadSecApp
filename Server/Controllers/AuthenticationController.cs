using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Unicode;
using System.Threading.Tasks;
using System.Xml;

namespace BadSecApp.Server.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthenticationController : Controller
    {
        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController(ILogger<AuthenticationController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public StatusCodeResult Login([FromQuery] string login, [FromQuery] string pwd)
        {
            if (login is null) throw new ArgumentException("login cannot be empty");
            if (pwd is null) pwd = string.Empty;
            
            bool isAuthenticated = true; // SECU (mettre un apostrophe) A vérifier : Par défaut on est connecté ? ( problèmatique surtout si on arrive a sortir du try and catch ex si on arrive a override la réponse sql ou a générer une erreur )
            try
            {
                var content = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(pwd));
                StringBuilder sb = new StringBuilder();
                foreach (byte b in content)
                    sb.Append(b.ToString("x2"));
                string hash = sb.ToString().ToLower();
                // SECU reverse MD5 avec le mot de passe "Superman" en dur ... le mieux ça serait de le hasher avec un algo beaucoup plus puissant (ex : SHA-256) + avoir l'admin directement en bdd et pas en dur dans le code
                // https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
                if (login == "admin" && hash != "84d961568a65073a3bcf0eb216b2a576") 
                    isAuthenticated = false;
                else if (login != "admin")
                {
                    using (var conn = new SqliteConnection("Data Source=test.db"))
                    {
                        conn.Open();
                        var commande = conn.CreateCommand();
                        commande.CommandText = "SELECT hash FROM USERS WHERE login='" + login + "'";
                        if (commande.ExecuteScalar()?.ToString() != hash) // SECU On pense que si on fait une injection sql et que l'on retourne directement la valeur du hash, on est considéré comme authentifié (voir également pour faire une injection avec une union d'un autre utilisateur)
                            //https://owasp.org/www-community/attacks/SQL_Injection
                            isAuthenticated = false;
                    }
                }
            }
            catch (Exception excep)
            {
                _logger.LogDebug(excep.ToString());
            }

            if (isAuthenticated)
            {
                HttpContext.Session.Set("USER", Encoding.UTF8.GetBytes(login));
                return new OkResult();
            }
            else
            {
                // SECU Cacher l'information que c'est un problème d'authenfication 
                // https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
                return new UnauthorizedResult();
            }
        }

        [HttpGet("validate")]
        public StatusCodeResult ValidateUsersList(string xmlContent)
        {
            // SECU Possibilité d'injecter du code xml (du coup on peut impacter très fortement les performances du serveur en faisant des références de pointeurs sur des pointeurs ..etc)
            // https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
            XmlDocument dom = new XmlDocument();
            dom.LoadXml(xmlContent);
            if (dom.SelectNodes("//users").Count > 0)
                return new OkResult();
            else
                return NotFound();
        }
    }
}
