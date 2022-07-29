using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Specialized;
using System.Text;
using System.Net;
using System.IO;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Diagnostics;
using System.Security.Principal;

namespace VelvetAuth
{
    public class api
    {
        public string program_version, program_key, api_key;

        private bool is_initialized,  show_messages, logged_in;
        public api(string version, string program_key, string api_key, bool show_messages = true)
        {
            this.program_version = version;

            this.program_key = program_key;

            this.api_key = api_key;

            this.show_messages = show_messages;
        }

        #region structures
        [DataContract]
        private class response_structure
        {
            [DataMember]
            public bool success { get; set; }

            [DataMember]
            public string response { get; set; }

            [DataMember]
            public string message { get; set; }

            [DataMember(IsRequired = false, EmitDefaultValue = false)]
            public user_data_structure user_data { get; set; }
        }

        [DataContract]
        private class user_data_structure
        {
            [DataMember]
            public string username { get; set; }

            [DataMember]
            public string email { get; set; }

            [DataMember]
            public string expires { get; set; } //timestamp

            [DataMember]
            public string var { get; set; }

            [DataMember]
            public int rank { get; set; }
        }
        #endregion

        private string session_id, session_iv;
        public void init()
        {
            try
            {
                session_iv = encryption.iv_key();

                var init_iv = encryption.sha256(session_iv); // can be changed to whatever you want

                var values_to_upload = new NameValueCollection
                {
                    ["version"] = encryption.encrypt(program_version, api_key, init_iv),
                    ["session_iv"] = encryption.encrypt(session_iv, api_key, init_iv),
                    ["api_version"] = encryption.encrypt("1.2", api_key, init_iv),

                    ["program_key"] = encryption.byte_arr_to_str(Encoding.Default.GetBytes(program_key)),
                    ["init_iv"] = init_iv
                };

                var response = do_request("init", values_to_upload);

                if (response == "program_doesnt_exist")
                {
                    messagebox.show("The program key you tried to use doesn't exist", messagebox.icons.error);

                    return;
                }

                response = encryption.decrypt(response, api_key, init_iv);

                var decoded_response = response_decoder.string_to_generic<response_structure>(response);

                if (!decoded_response.success)
                    messagebox.show(decoded_response.message, messagebox.icons.error);

                var response_data = decoded_response.response.Split('|');

                if (response_data[0] == "wrong_version")
                {
                    Process.Start(response_data[1]);

                    return;
                }

                is_initialized = true;

                session_iv += response_data[1];

                session_id = response_data[2];
            }
            catch (CryptographicException)
            {
                messagebox.show("Invalid API/Encryption key", messagebox.icons.error);

                return;
            }
        }

        public bool login(string username, string password, string hwid = null)
        {
            if (hwid == null) hwid = WindowsIdentity.GetCurrent().User.Value;

            if (!is_initialized)
            {
                messagebox.show("The program wasn't initialized", messagebox.icons.error);

                return false;
            }

            var values_to_upload = new NameValueCollection
            {
                ["username"] = encryption.encrypt(username, api_key, session_iv),
                ["password"] = encryption.encrypt(password, api_key, session_iv),
                ["hwid"] = encryption.encrypt(hwid, api_key, session_iv),

                ["sessid"] = encryption.byte_arr_to_str(Encoding.Default.GetBytes(session_id))
            };

            var response = do_request("login", values_to_upload);

            response = encryption.decrypt(response, api_key, session_iv);

            var decoded_response = response_decoder.string_to_generic<response_structure>(response);

            logged_in = decoded_response.success;

            if (!logged_in && show_messages)
                messagebox.show(decoded_response.message, messagebox.icons.error);
            else if (logged_in)
                load_user_data(decoded_response.user_data);

            return logged_in;
        }

        public bool register(string username, string email, string password, string token, string hwid = null)
        {
            if (hwid == null) hwid = WindowsIdentity.GetCurrent().User.Value;

            if (!is_initialized)
            {
                messagebox.show("The program wasn't initialized", messagebox.icons.error);

                return false;
            }

            var values_to_upload = new NameValueCollection
            {
                ["username"] = encryption.encrypt(username, api_key, session_iv),
                ["email"] = encryption.encrypt(email, api_key, session_iv),
                ["password"] = encryption.encrypt(password, api_key, session_iv),
                ["token"] = encryption.encrypt(token, api_key, session_iv),
                ["hwid"] = encryption.encrypt(hwid, api_key, session_iv),

                ["sessid"] = encryption.byte_arr_to_str(Encoding.Default.GetBytes(session_id))
            };

            var response = do_request("register", values_to_upload);

            response = encryption.decrypt(response, api_key, session_iv);

            var decoded_response = response_decoder.string_to_generic<response_structure>(response);

            if (!decoded_response.success && show_messages)
                messagebox.show(decoded_response.message, messagebox.icons.error);

            return decoded_response.success;
        }

        public bool activate(string username, string token)
        {
            if (!is_initialized)
            {
                messagebox.show("The program wasn't initialized", messagebox.icons.error);

                return false;
            }

            var values_to_upload = new NameValueCollection
            {
                ["username"] = encryption.encrypt(username, api_key, session_iv),
                ["token"] = encryption.encrypt(token, api_key, session_iv),

                ["sessid"] = encryption.byte_arr_to_str(Encoding.Default.GetBytes(session_id))
            };

            var response = do_request("activate", values_to_upload);

            response = encryption.decrypt(response, api_key, session_iv);

            var decoded_response = response_decoder.string_to_generic<response_structure>(response);

           // if (!decoded_response.success && show_messages)
             //   messagebox.show(decoded_response.message, messagebox.icons.error);

            return decoded_response.success;
        }

        public bool all_in_one(string token, string hwid = null)
        {
            if (hwid == null) hwid = WindowsIdentity.GetCurrent().User.Value;

            if (login(token, token, hwid))
                return true;

            else if (register(token, token + "@email.com", token, token, hwid))
            {
                Environment.Exit(0);
                return true;
            }

            return false;
        }

        public byte[] file(string file_name, string hwid = null)
        {
            if (hwid == null) hwid = WindowsIdentity.GetCurrent().User.Value;

            if (!is_initialized)
            {
                messagebox.show("The program wasn't initialized", messagebox.icons.error);

                return Encoding.Default.GetBytes("not_initialized");
            }

            if (!logged_in)
            {
                messagebox.show("You can only grab server sided variables after being logged in.", messagebox.icons.error);

                return Encoding.Default.GetBytes("not_initialized");
            }

            var values_to_upload = new NameValueCollection
            {
                ["file_name"] = encryption.encrypt(file_name, api_key, session_iv),
                ["sessid"] = encryption.byte_arr_to_str(Encoding.Default.GetBytes(session_id))
            };

            var response = do_request("file", values_to_upload);

            response = encryption.decrypt(response, api_key, session_iv);

            var decoded_response = response_decoder.string_to_generic<response_structure>(response);

            if (!decoded_response.success && show_messages)
                messagebox.show(decoded_response.message, messagebox.icons.error);

            return encryption.str_to_byte_arr(decoded_response.response);
        }

        public string var(string var_name, string hwid = null)
        {
            if (hwid == null) hwid = WindowsIdentity.GetCurrent().User.Value;

            if (!is_initialized)
            {
                messagebox.show("The program wasn't initialized", messagebox.icons.error);

                return "not_initialized";
            }

            if (!logged_in)
            {
                messagebox.show("You can only grab server sided variables after being logged in.", messagebox.icons.error);

                return "not_logged_in";
            }

            var values_to_upload = new NameValueCollection
            {
                ["var_name"] = encryption.encrypt(var_name, api_key, session_iv),
                ["sessid"] = encryption.byte_arr_to_str(Encoding.Default.GetBytes(session_id))
            };

            var response = do_request("var", values_to_upload);

            response = encryption.decrypt(response, api_key, session_iv);

            var decoded_response = response_decoder.string_to_generic<response_structure>(response);

            if (!decoded_response.success && show_messages)
                messagebox.show(decoded_response.message, messagebox.icons.error);

            return decoded_response.response;
        }

        public void log(string message)
        {
            if (user_data.username == null) user_data.username = "NONE";

            if (!is_initialized)
            {
                messagebox.show("The program wasn't initialized", messagebox.icons.error);

                return;
            }

            var values_to_upload = new NameValueCollection
            {
                ["username"] = encryption.encrypt(user_data.username, api_key, session_iv),
                ["message"] = encryption.encrypt(message, api_key, session_iv),
                ["sessid"] = encryption.byte_arr_to_str(Encoding.Default.GetBytes(session_id))
            };

            do_request("log", values_to_upload);
        }

        private string do_request(string type, NameValueCollection post_data)
        {
            using (WebClient client = new WebClient())
            {
                client.Headers["User-Agent"] = "vAuthentication";

                ServicePointManager.ServerCertificateValidationCallback = others.pin_public_key;

                var raw_response = client.UploadValues("https://velvetauth.com/auth/api/handler.php" + "?type=" + type, post_data);

                ServicePointManager.ServerCertificateValidationCallback += (send, certificate, chain, sslPolicyErrors) => { return true; };

                return Encoding.Default.GetString(raw_response);
            }
        }

        #region user_data
        public user_data_class user_data = new user_data_class();

        public class user_data_class
        {
            public string username { get; set; }
            public string email { get; set; }
            public DateTime expires { get; set; }
            public string var { get; set; }
            public int rank { get; set; }
        }
        private void load_user_data(user_data_structure data)
        {
            user_data.username = data.username;

            user_data.email = data.email;

            user_data.expires = others.unix_to_date(Convert.ToDouble(data.expires));

            user_data.var = data.var;

            user_data.rank = data.rank;
        }
        #endregion

        private string api_endpoint = "https://velvetauth.com/auth/api/handler.php";

        private string user_agent = "Mozilla vAuthentication";

        private json_wrapper response_decoder = new json_wrapper(new response_structure());
    }

    public static class others
    {
        public static DateTime unix_to_date(double unixTimeStamp) =>
    new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc).AddSeconds(unixTimeStamp).ToLocalTime();

        public static bool pin_public_key(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) =>
            certificate.GetPublicKeyString() == "3082010A0282010100CE579FBB0AC2D7F1634EFBF744FC448055F6D5F62CDEAAB2C578F909803BC724A5EC0BFC6FDA00495C4FFD912C54E4E24AC6AE8C7F1A9ECA651D70EDDD58194E1FFDFC0D5C1E461E3FB2870B1928891943DDE8B2AB9105CB9E6433C70398D007A6C37EE4AD73AD84D3E286B33E93BF427F9D21090C9B40EEB5DCEA30D44AA517A4EC7576A891A3751E89D8A484D7BA69B70ABCA878111D4A374507C0E93AEDFD4AC2A1248BE25201ABC4D9A5106AF687ABDC4583937CC1339ADF5067FD42DC4448B1F6E2D9FA528E95050474C7247805691F793D241E912C751197C18970A6C96E51DE45D5E2AB3C94D2FA425F46A1C4D4EA9F93F90DA4BC63DF64216DCE76810203010001";
    }

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
            certificate.GetPublicKeyString() == "3082010A0282010100CE579FBB0AC2D7F1634EFBF744FC448055F6D5F62CDEAAB2C578F909803BC724A5EC0BFC6FDA00495C4FFD912C54E4E24AC6AE8C7F1A9ECA651D70EDDD58194E1FFDFC0D5C1E461E3FB2870B1928891943DDE8B2AB9105CB9E6433C70398D007A6C37EE4AD73AD84D3E286B33E93BF427F9D21090C9B40EEB5DCEA30D44AA517A4EC7576A891A3751E89D8A484D7BA69B70ABCA878111D4A374507C0E93AEDFD4AC2A1248BE25201ABC4D9A5106AF687ABDC4583937CC1339ADF5067FD42DC4448B1F6E2D9FA528E95050474C7247805691F793D241E912C751197C18970A6C96E51DE45D5E2AB3C94D2FA425F46A1C4D4EA9F93F90DA4BC63DF64216DCE76810203010001";
    }

    public static class messagebox
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int MessageBox(IntPtr hWND, string message, string caption, uint icon);

        public enum icons : long
        {
            exclamation = 0x00000030L,
            warning = 0x00000030L,
            information = 0x00000040L,
            asterisk = 0x00000040L,
            question = 0x00000020L,
            stop = 0x00000010L,
            error = 0x00000010L,
            hand = 0x00000010L
        }

        public static int show(string text, icons ico)
        {
            return MessageBox((IntPtr)0, text, "vAuthentication", (uint)ico);
        }
    }

    public class json_wrapper
    {
        public static bool is_serializable(Type to_check) =>
            to_check.IsSerializable || to_check.IsDefined(typeof(DataContractAttribute), true);

        public json_wrapper(object obj_to_work_with)
        {
            current_object = obj_to_work_with;

            var object_type = current_object.GetType();

            serializer = new DataContractJsonSerializer(object_type);

            if (!is_serializable(object_type))
                throw new Exception($"the object {current_object} isn't a serializable");
        }

        public string to_json_string()
        {
            using (var mem_stream = new MemoryStream())
            {
                serializer.WriteObject(mem_stream, current_object);

                mem_stream.Position = 0;

                using (var reader = new StreamReader(mem_stream))
                    return reader.ReadToEnd();
            }
        }

        public object string_to_object(string json)
        {
            var buffer = Encoding.Default.GetBytes(json);

            //SerializationException = session expired

            using (var mem_stream = new MemoryStream(buffer))
                return serializer.ReadObject(mem_stream);
        }

        #region extras

        public dynamic string_to_dynamic(string json) =>
            (dynamic)string_to_object(json);

        public T string_to_generic<T>(string json) =>
            (T)string_to_object(json);

        public dynamic to_json_dynamic() =>
            string_to_object(to_json_string());

        #endregion

        private DataContractJsonSerializer serializer;

        private object current_object;
    }
}
