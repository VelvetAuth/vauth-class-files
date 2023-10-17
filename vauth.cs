using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using vProtect.api;

namespace VelvetAuth
{
    public class api
    {
        public string program_version, program_key, api_key;

        private bool is_initialized, show_messages, logged_in;
        public api(string version, string program_key, string api_key, bool show_messages = true)
        {
            if (string.IsNullOrEmpty(version))
            {
                throw new ArgumentException($"'{nameof(version)}' cannot be null or empty.", nameof(version));
            }

            if (string.IsNullOrEmpty(program_key))
            {
                throw new ArgumentException($"'{nameof(program_key)}' cannot be null or empty.", nameof(program_key));
            }

            if (string.IsNullOrEmpty(api_key))
            {
                throw new ArgumentException($"'{nameof(api_key)}' cannot be null or empty.", nameof(api_key));
            }

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
            public int rank { get; set; }
        }
        #endregion

        private string session_id, session_iv;
        public void ServerResponse()
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

        public bool LoginResponse(string username, string password, string hwid = null)
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

        public bool RegisterResponse(string username, string email, string password, string token, string hwid = null)
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

        public bool UpdateResponse(string username, string token)
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

        public bool ResponeKey(string token, string hwid = null)
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

      

  

  

       

        private string do_request(string type, NameValueCollection post_data)
        {
            using (WebClient client = new WebClient())
            {
                client.Headers["User-Agent"] = "velvetauth";

                ServicePointManager.ServerCertificateValidationCallback = encryption.pin_public_key;

                var raw_response = client.UploadValues("https://velvetauth.xyz/api/handler.php" + "?type=" + type, post_data);

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
            public int rank { get; set; }
        }
        private void load_user_data(user_data_structure data)
        {
            user_data.username = data.username;

            user_data.email = data.email;

            user_data.expires = encryption.unix_to_date(Convert.ToDouble(data.expires));


            user_data.rank = data.rank;
        }
        #endregion

      

        private json_wrapper response_decoder = new json_wrapper(new response_structure());
    }

}
