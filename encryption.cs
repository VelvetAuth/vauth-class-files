using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace vProtect.api
{
    public static class encryption
    {
        public static string byte_arr_to_str(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static byte[] str_to_byte_arr(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static string encrypt_string(string plain_text, byte[] key, byte[] iv)
        {
            Aes encryptor = Aes.Create();

            encryptor.Mode = CipherMode.CBC;
            encryptor.Key = key;
            encryptor.IV = iv;

            using (MemoryStream mem_stream = new MemoryStream())
            {
                using (ICryptoTransform aes_encryptor = encryptor.CreateEncryptor())
                {
                    using (CryptoStream crypt_stream = new CryptoStream(mem_stream, aes_encryptor, CryptoStreamMode.Write))
                    {
                        byte[] p_bytes = Encoding.Default.GetBytes(plain_text);

                        crypt_stream.Write(p_bytes, 0, p_bytes.Length);

                        crypt_stream.FlushFinalBlock();

                        byte[] c_bytes = mem_stream.ToArray();

                        return byte_arr_to_str(c_bytes);
                    }
                }
            }
        }

        public static string decrypt_string(string cipher_text, byte[] key, byte[] iv)
        {
            Aes encryptor = Aes.Create();

            encryptor.Mode = CipherMode.CBC;
            encryptor.Key = key;
            encryptor.IV = iv;

            using (MemoryStream mem_stream = new MemoryStream())
            {
                using (ICryptoTransform aes_decryptor = encryptor.CreateDecryptor())
                {
                    using (CryptoStream crypt_stream = new CryptoStream(mem_stream, aes_decryptor, CryptoStreamMode.Write))
                    {
                        byte[] c_bytes = str_to_byte_arr(cipher_text);

                        crypt_stream.Write(c_bytes, 0, c_bytes.Length);

                        crypt_stream.FlushFinalBlock();

                        byte[] p_bytes = mem_stream.ToArray();

                        return Encoding.Default.GetString(p_bytes, 0, p_bytes.Length);
                    }
                }
            }
        }

        public static string iv_key() =>
            Guid.NewGuid().ToString().Substring(0, Guid.NewGuid().ToString().IndexOf("-", StringComparison.Ordinal));

        public static string sha256(string r) =>
            byte_arr_to_str(new SHA256Managed().ComputeHash(Encoding.Default.GetBytes(r)));

        public static string encrypt(string message, string enc_key, string iv)
        {
            byte[] _key = Encoding.Default.GetBytes(sha256(enc_key).Substring(0, 32));

            byte[] _iv = Encoding.Default.GetBytes(sha256(iv).Substring(0, 16));

            return encrypt_string(message, _key, _iv);
        }

        public static string decrypt(string message, string enc_key, string iv)
        {
            byte[] _key = Encoding.Default.GetBytes(sha256(enc_key).Substring(0, 32));

            byte[] _iv = Encoding.Default.GetBytes(sha256(iv).Substring(0, 16));

            return decrypt_string(message, _key, _iv);
        }

        public static DateTime unix_to_date(double unixTimeStamp) =>
            new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc).AddSeconds(unixTimeStamp).ToLocalTime();

        public static bool pin_public_key(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) =>
            certificate.GetPublicKeyString() == "3082010A0282010100E961B1E4891C571FE2DDFDE0C2EEBB61DBD14E87A46BA85169D063959EF564994BDA92B5DB9BD85A43CC5A5F8810A529D8173E446D6D63B54597F62DA9E06056E180E30717BBD0B528CDC7A14E882C7499265BF3920F86CAE8698E7B279484A6270514022094F27FD221CFD95C472D2C5BABE13E2FB43AD0F25F9A4F40C32A7BC5959E3003BBAC6C12474EB758E51074E6FE65C33A3AAFADB0464EEC231C08D8A44143DDAE02E8826EA95A1D1CB1B6DFB592DE908AAE03A24F03DE5169F3706CC5ECBE322DED8B70F6CC7266DBB274C75342D6F5C62FBB1A99EC43B3291C929E4E975B0FB7DD4C6AACA1150EDE9D7801B364E44618BA2085647F3E2858FFA7E10203010001";
    }
}
