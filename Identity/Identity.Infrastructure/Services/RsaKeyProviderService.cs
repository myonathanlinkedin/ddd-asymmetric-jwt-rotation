using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Identity.Infrastructure.Services
{
    public class RsaKeyProviderService : IRsaKeyProvider
    {
        private const string SignatureUse = "sig";

        private RSA rsa;
        private JsonWebKey jsonWebKey;
        private string keyId;

        public RsaKeyProviderService(IOptions<ApplicationSettings> appSettings)
        {
            var rotationInterval = TimeSpan.FromSeconds(appSettings.Value.KeyRotationIntervalSeconds);

            GenerateKeys();

            new Timer(_ => GenerateKeys(), null, rotationInterval, rotationInterval);
        }

        private void GenerateKeys()
        {
            rsa?.Dispose();
            rsa = RSA.Create(2048);
            keyId = Guid.NewGuid().ToString();

            var rsaSecurityKey = new RsaSecurityKey(rsa.ExportParameters(false))
            {
                KeyId = keyId
            };

            jsonWebKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaSecurityKey);
            jsonWebKey.Use = SignatureUse;
        }

        public RSA GetPrivateKey() => rsa;

        public JsonWebKey GetPublicJwk() => jsonWebKey;
    }
}
