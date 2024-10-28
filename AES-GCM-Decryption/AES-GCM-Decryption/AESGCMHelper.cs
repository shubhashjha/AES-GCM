using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AES_GCM_Decryption
{
    internal class AESGCMHelper
    {
        public static string Decrypt(string encryptedBase64, string keyBase64, string nonceBase64)
        {
            // Convert key, nonce, and encrypted data from base64 to byte arrays
            byte[] key = Convert.FromBase64String(keyBase64);
            byte[] nonce = Convert.FromBase64String(nonceBase64);
            byte[] encryptedData = Convert.FromBase64String(encryptedBase64);

            // Extract the tag (last 16 bytes of encrypted data)
            byte[] ciphertext = encryptedData[..^16];
            byte[] tag = encryptedData[^16..];

            // Prepare buffer for decrypted data
            byte[] decryptedData = new byte[ciphertext.Length];

            // Decrypt using AesGcm
            using (var aesGcm = new AesGcm(key))
            {
                aesGcm.Decrypt(nonce, ciphertext, tag, decryptedData);
            }

            return Encoding.UTF8.GetString(decryptedData);
        }
    }
}
