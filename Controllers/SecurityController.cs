using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace encryption.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecurityController : ControllerBase
    {

        //https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/using-data-protection?view=aspnetcore-2.2
        // GET api/values/key
        [HttpGet("{key}")]
        public ActionResult<IEnumerable<string>> Get(string key)
        {
            //METHOD1 Two Way
            //-------------------------------------------------------------------------
            var SCollection = new ServiceCollection();

            //add protection services
            SCollection.AddDataProtection();
            var LockerKey = SCollection.BuildServiceProvider();

            // create an instance of classfile using 'CreateInstance' method
            var locker = ActivatorUtilities.CreateInstance<Security>(LockerKey);
            //string encryptKey = locker.Encrypt(key);
            //string deencryptKey = locker.Decrypt(encryptKey);
            //return new string[] { encryptKey, deencryptKey};

            //https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.cryptography.keyderivation.keyderivation.pbkdf2?view=aspnetcore-2.1
            //METHOD2 One Way
            //-------------------------------------------------------------------------
            string salt = locker.HashCreate();
            string encryptKey = locker.HashCreate(key, salt);

            string getEncryptKey = encryptKey.Split('æ')[0];
            string getSalt=encryptKey.Split('æ')[1];
            string result = locker.ValidateHash(key, getSalt, getEncryptKey).ToString();
            //string deencryptKey = locker.ValidateHash(key, salt, encryptKey).ToString();

            return new string[] { encryptKey, result, salt };
        }

        // POST api/values
        [HttpPost]
        public void Post([FromBody] string value)
        {
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
