namespace CommonServices.Common
{
    #region Using
    using System;
    using System.Collections;
    using System.ComponentModel;
    using System.Linq;
    using System.Text;
    using System.IO;
    using System.Security.Cryptography;
    #endregion

    public class Encryption
    {
        #region Properties

        #endregion

        #region Enumerations
        /// <summary>
        /// List of Algorithms.
        /// </summary>
        public enum EncryptionAlgorithm
        {
            [Description("NONE")]
            NONE,
            [Description("AES_128")]
            AES_128,
            [Description("AES_192")]
            AES_192,
            [Description("AES_256")]
            AES_256,
            [Description("DES")]
            DES,
            [Description("DESX")]
            DESX,
            [Description("TRIPLE_DES")]
            TRIPLE_DES,
            [Description("RC2")]
            RC2,
            [Description("RC4")]
            RC4
        }

        /// <summary>
        /// List of what can be encrypted. 
        /// </summary>
        public enum WhatToEncrypt
        {
            [Description("Nothing")]
            None = 0,
            [Description("Credentials")]
            Credentials = 1,
            [Description("Words")]
            Words = 2,
            [Description("WholePhrase")]
            WholePhrase = 3
        }
        #endregion

        #region Get Encryption Algorithm to be used
        /// <summary>
        /// It gets the correct Encryption Algorithm to be used.
        /// </summary>
        /// <param name="encType">Name of the Algorithm.</param>
        /// <returns>
        ///   Encryption.EncryptionAlgorithm to be used.
        /// </returns>
        public static Encryption.EncryptionAlgorithm GetEncryptionGeneralType(String encType)
        {
            Encryption.EncryptionAlgorithm algorithm = Encryption.EncryptionAlgorithm.NONE;

            // Selecting the correct Algorithm
            switch (encType)
            {
                case "AES_128":
                    algorithm = Encryption.EncryptionAlgorithm.AES_128;
                    break;
                case "AES_192":
                    algorithm = Encryption.EncryptionAlgorithm.AES_192;
                    break;
                case "AES_256":
                    algorithm = Encryption.EncryptionAlgorithm.AES_256;
                    break;
                case "DES":
                    algorithm = Encryption.EncryptionAlgorithm.DES;
                    break;
                case "DESX":
                    algorithm = Encryption.EncryptionAlgorithm.DESX;
                    break;
                case "TRIPLE_DES":
                    algorithm = Encryption.EncryptionAlgorithm.TRIPLE_DES;
                    break;
                case "RC2":
                    algorithm = Encryption.EncryptionAlgorithm.RC2;
                    break;
                case "RC4":
                    algorithm = Encryption.EncryptionAlgorithm.RC4;
                    break;
                case "NONE":
                    algorithm = Encryption.EncryptionAlgorithm.NONE;
                    break;
                default:
                    algorithm = Encryption.EncryptionAlgorithm.DES;
                    break;
            }
            return algorithm;
        }
        #endregion

        #region Encrypt - Decrypt
        #region Encrypt
        /// <summary>
        /// Encrypt a phrase.
        /// </summary>
        /// <param name="phrase">Phrase to be Encrypted.</param>
        /// <param name="encriptionAlgorithm">Used algorithm.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns></returns>
        public static string Encrypt(string phrase, EncryptionAlgorithm encriptionAlgorithm, string key)
        {
            string response = string.Empty;

            // Selecting the correct Algorithm
            switch (encriptionAlgorithm)
            {
                case EncryptionAlgorithm.NONE:
                    response = Encrypt_NONE(phrase, key);
                    break;
                case EncryptionAlgorithm.AES_128:
                    response = Encrypt_AES_128(phrase, key);
                    break;
                case EncryptionAlgorithm.AES_192:
                    response = Encrypt_AES_192(phrase, key);
                    break;
                case EncryptionAlgorithm.AES_256:
                    response = Encrypt_AES_256(phrase, key);
                    break;
                case EncryptionAlgorithm.DES:
                    response = Encrypt_DES(phrase, key);
                    break;
                case EncryptionAlgorithm.DESX:
                    response = Encrypt_DESX(phrase, key);
                    break;
                case EncryptionAlgorithm.RC2:
                    response = Encrypt_RC2(phrase, key);
                    break;
                case EncryptionAlgorithm.RC4:
                    response = Encrypt_RC4(phrase, key);
                    break;
                case EncryptionAlgorithm.TRIPLE_DES:
                    response = Encrypt_TRIPLE_DES(phrase, key);
                    break;
            }

            return response;
        }
        #endregion

        #region Decrypt
        /// <summary>
        /// Decrypt a phrase.
        /// </summary>
        /// <param name="phrase">Phrase to be Decrypted.</param>
        /// <param name="encriptionAlgorithm">Used algorithm.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns></returns>
        public static string Decrypt(string phrase, EncryptionAlgorithm encriptionAlgorithm, string key)
        {
            string response = string.Empty;

            // Selecting the correct Algorithm
            switch (encriptionAlgorithm)
            {
                case EncryptionAlgorithm.NONE:
                    response = Decrypt_NONE(phrase, key);
                    break;
                case EncryptionAlgorithm.AES_128:
                    response = Decrypt_AES_128(phrase, key);
                    break;
                case EncryptionAlgorithm.AES_192:
                    response = Decrypt_AES_192(phrase, key);
                    break;
                case EncryptionAlgorithm.AES_256:
                    response = Decrypt_AES_256(phrase, key);
                    break;
                case EncryptionAlgorithm.DES:
                    response = Decrypt_DES(phrase, key);
                    break;
                case EncryptionAlgorithm.DESX:
                    response = Decrypt_DESX(phrase, key);
                    break;
                case EncryptionAlgorithm.RC2:
                    response = Decrypt_RC2(phrase, key);
                    break;
                case EncryptionAlgorithm.RC4:
                    response = Decrypt_RC4(phrase, key);
                    break;
                case EncryptionAlgorithm.TRIPLE_DES:
                    response = Decrypt_TRIPLE_DES(phrase, key);
                    break;
            }

            return response;
        }
        #endregion
        #endregion

        #region Algorithms
        #region Standard Algorithms
        #region NONE
        /// <summary>
        /// Encrypting using NONE.
        /// </summary>
        /// <param name="textToEncrypt">Text to be encrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Encrypted text.
        /// </returns>
        private static string Encrypt_NONE(string textToEncrypt, string key)
        {
            string response  = textToEncrypt;

            return response;
        }
        /// <summary>
        /// Decrypting using NONE.
        /// </summary>
        /// <param name="textToDecrypt">Text to be encrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Decrypted text.
        /// </returns>
        private static string Decrypt_NONE(string textToDecrypt, string key)
        {
            string response = textToDecrypt;

            return response;
        }
        #endregion

        #region TRIPLE_DES
        /// <summary>
        /// Encrypting using TRIPLE_DES.
        /// </summary>
        /// <param name="textToEncrypt">Text to be encrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Encrypted text.
        /// </returns>
        private static string Encrypt_TRIPLE_DES(string textToEncrypt, string key)
        {
            string response = string.Empty;

            try
            {
                // Bytes for the key
                byte[] keyArray;
                // Bytes with the string to encrypt
                byte[] Array_to_Encrypt = UTF8Encoding.UTF8.GetBytes(textToEncrypt);

                // Preparing Algorithm MD5
                MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
                // Using key by hashing
                keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
                hashmd5.Clear();

                // Algorithm 3DAS
                TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
                tdes.Key = keyArray;
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;

                // Starting encryption
                ICryptoTransform cTransform = tdes.CreateEncryptor();
                // Bytes with encrypted string
                byte[] resultArray = cTransform.TransformFinalBlock(Array_to_Encrypt, 0, Array_to_Encrypt.Length);
                tdes.Clear();

                // Giving the encrypted text as string
                response = Convert.ToBase64String(resultArray, 0, resultArray.Length);
            }
            catch
            {
            }

            return response;
        }
        /// <summary>
        /// Decrypting using TRIPLE_DES.
        /// </summary>
        /// <param name="textToDecrypt">Text to be decrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Decrypted text.
        /// </returns>
        private static string Decrypt_TRIPLE_DES(string textToDecrypt, string key)
        {
            string response = string.Empty;

            try
            {
                // Bytes for the key
                byte[] keyArray;
                // Bytes with the string to decrypt
                byte[] Array_to_Decrypt = Convert.FromBase64String(textToDecrypt);

                // Preparing Algorithm MD5
                MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
                // Using key by hashing
                keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
                hashmd5.Clear();

                // Algorithm 3DAS
                TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
                tdes.Key = keyArray;
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;

                // Starting decryption
                ICryptoTransform cTransform = tdes.CreateDecryptor();
                // Bytes with decrypted string
                byte[] resultArray = cTransform.TransformFinalBlock(Array_to_Decrypt, 0, Array_to_Decrypt.Length);
                tdes.Clear();

                // Giving the result as string
                response = UTF8Encoding.UTF8.GetString(resultArray);
            }
            catch
            {
            }

            return response;
        }
        #endregion

        #region DES
        /// <summary>
        /// Encrypting using DES.
        /// </summary>
        /// <param name="textToEncrypt">Text to be encrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Encrypted text.
        /// </returns>
        private static string Encrypt_DES(string textToEncrypt, string key)
        {
            string response = string.Empty;

            try
            {
                byte[] bytes = ASCIIEncoding.ASCII.GetBytes(key.Substring(0, 8));

                DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
                MemoryStream memoryStream = new MemoryStream();
                CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoProvider.CreateEncryptor(bytes, bytes), CryptoStreamMode.Write);
                StreamWriter writer = new StreamWriter(cryptoStream);
                writer.Write(textToEncrypt);
                writer.Flush();
                cryptoStream.FlushFinalBlock();
                writer.Flush();

                response = Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length);
            }
            catch
            {
            }

            return response;
        }
        /// <summary>
        /// Decrypting using DES.
        /// </summary>
        /// <param name="textToDecrypt">Text to be decrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Decrypted text.
        /// </returns>
        private static string Decrypt_DES(string textToDecrypt, string key)
        {
            string response = string.Empty;

            try
            {
                byte[] bytes = ASCIIEncoding.ASCII.GetBytes(key.Substring(0, 8));

                DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
                MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(textToDecrypt));
                CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoProvider.CreateDecryptor(bytes, bytes), CryptoStreamMode.Read);
                StreamReader reader = new StreamReader(cryptoStream);

                response = reader.ReadToEnd();
            }
            catch
            {
            }

            return response;
        }
        #endregion
        
        #region XDES
        /// <summary>
        /// Encrypting using DESX.
        /// </summary>
        /// <param name="textToEncrypt">Text to be encrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Encrypted text.
        /// </returns>
        /// <remarks>
        ///    DESX was incorrectly named. Symmetric keys created with ALGORITHM = DESX actually use the TRIPLE DES cipher with a 192-bit key. <BR/>
        ///    The DESX algorithm is not provided. This feature will be removed in a future version of Microsoft SQL Server.
        /// </remarks>
        private static string Encrypt_DESX(string textToEncrypt, string key)
        {
            string response = string.Empty;

            try
            {
                // DESX was incorrectly named. Symmetric keys created with ALGORITHM = DESX actually use the TRIPLE DES cipher with a 192-bit key. 
                // The DESX algorithm is not provided. This feature will be removed in a future version of Microsoft SQL Server.
                Decrypt_TRIPLE_DES(textToEncrypt, key);
            }
            catch
            {
            }

            return response;
        }
        /// <summary>
        /// Decrypting using DESX.
        /// </summary>
        /// <param name="textToDecrypt">Text to be decrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Decrypted text.
        /// </returns>
        /// <remarks>
        ///    DESX was incorrectly named. Symmetric keys created with ALGORITHM = DESX actually use the TRIPLE DES cipher with a 192-bit key. <BR/>
        ///    The DESX algorithm is not provided. This feature will be removed in a future version of Microsoft SQL Server.
        /// </remarks>
        private static string Decrypt_DESX(string textToDecrypt, string key)
        {
            string response = string.Empty;

            try
            {
                // DESX was incorrectly named. Symmetric keys created with ALGORITHM = DESX actually use the TRIPLE DES cipher with a 192-bit key.
                // The DESX algorithm is not provided. This feature will be removed in a future version of Microsoft SQL Server.
                Decrypt_TRIPLE_DES(textToDecrypt, key);
            }
            catch
            {
            }

            return response;
        }
        #endregion

        #region RC2
        /// <summary>
        /// Encrypting using RC2.
        /// </summary>
        /// <param name="textToEncrypt">Text to be encrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Encrypted text.
        /// </returns>
        private static string Encrypt_RC2(string textToEncrypt, string key)
        {
            string response = string.Empty;

            try
            {
                byte[] plaintext = Encoding.UTF8.GetBytes(textToEncrypt);
                byte[] password = Encoding.UTF8.GetBytes(key);
                PasswordDeriveBytes cdk = new PasswordDeriveBytes(password, null);
                byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
                byte[] keyRc2 = cdk.CryptDeriveKey("RC2", "MD5", 0, iv);
                RC2CryptoServiceProvider rc2 = new RC2CryptoServiceProvider();
                rc2.Key = keyRc2;
                rc2.IV = iv;    //IV MUST be specified with Zeroes, or it will be defaulted to a random value
                MemoryStream ms = new MemoryStream();
                CryptoStream cs = new CryptoStream(ms, rc2.CreateEncryptor(), CryptoStreamMode.Write);
                cs.Write(plaintext, 0, plaintext.Length);
                cs.Close();
                string str = BitConverter.ToString(ms.ToArray());
                str = str.Replace("-", "");  //formats output of BitConvertor to AutoIT binary formatted as string

                response = str;
            }
            catch
            {
            }

            return response;
        }
        /// <summary>
        /// Decrypting using RC2.
        /// </summary>
        /// <param name="textToDecrypt">Text to be decrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Decrypted text.
        /// </returns>
        private static string Decrypt_RC2(string textToDecrypt, string key)
        {
            string response = string.Empty;

            try
            {
                string encData = textToDecrypt;
                byte[] password = Encoding.UTF8.GetBytes(key);
                PasswordDeriveBytes cdk = new PasswordDeriveBytes(password, null);
                byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
                byte[] keyRC2 = cdk.CryptDeriveKey("RC2", "MD5", 0, iv);
                RC2CryptoServiceProvider rc2 = new RC2CryptoServiceProvider();
                rc2.Key = keyRC2;
                rc2.IV = iv;
                //Use Linq to convert the string to a byte array
                byte[] encrypted = Enumerable.Range(0, encData.Length)
                    .Where(x => x % 2 == 0)
                    .Select(x => Convert.ToByte(encData.Substring(x, 2), 16))
                    .ToArray();
                MemoryStream ms = new MemoryStream(encrypted);
                string plaintext = null;
                CryptoStream cs = new CryptoStream(ms, rc2.CreateDecryptor(), CryptoStreamMode.Read);
                StreamReader srDecrypt = new StreamReader(cs);
                plaintext = srDecrypt.ReadToEnd();

                response = plaintext;
            }
            catch
            {
            }

            return response;
        }
        #endregion

        #region RC4
        /// <summary>
        /// Encrypting using RC4.
        /// </summary>
        /// <param name="textToEncrypt">Text to be encrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Encrypted text.
        /// </returns>
        private static string Encrypt_RC4(string textToEncrypt, string key)
        {
            string response = string.Empty;

            try
            {
                long m_nBoxLen = 255;
                byte[] m_nBox = new byte[m_nBoxLen];
                string m_sEncryptionKey = "";
                string m_sEncryptionKeyAscii = "";

                #region Encryption Key part
                // Encryption Key part
                if (m_sEncryptionKey != key)
                {
                    m_sEncryptionKey = key;

                    //
                    // Used to populate m_nBox
                    //
                    long index2 = 0;

                    //
                    // Create two different encoding 
                    //
                    Encoding ascii = Encoding.ASCII;
                    Encoding unicode = Encoding.Unicode;

                    //
                    // Perform the conversion of the encryption key from unicode to ansi
                    //
                    byte[] asciiBytes = Encoding.Convert(unicode, ascii, unicode.GetBytes(m_sEncryptionKey));

                    //
                    // Convert the new byte[] into a char[] and then to string
                    //

                    char[] asciiChars = new char[ascii.GetCharCount(asciiBytes, 0, asciiBytes.Length)];
                    ascii.GetChars(asciiBytes, 0, asciiBytes.Length, asciiChars, 0);
                    m_sEncryptionKeyAscii = new string(asciiChars);

                    //
                    // Populate m_nBox
                    //
                    long KeyLen = m_sEncryptionKey.Length;

                    //
                    // First Loop
                    //
                    for (long count = 0; count < m_nBoxLen; count++)
                    {
                        m_nBox[count] = (byte)count;
                    }

                    //
                    // Second Loop
                    //
                    for (long count = 0; count < m_nBoxLen; count++)
                    {
                        index2 = (index2 + m_nBox[count] + asciiChars[count % KeyLen]) % m_nBoxLen;
                        byte temp = m_nBox[count];
                        m_nBox[count] = m_nBox[index2];
                        m_nBox[index2] = temp;
                    }

                }
                #endregion

                #region Encryption algorithm part
                //
                // indexes used below
                //
                long i = 0;
                long j = 0;

                //
                // Put input string in temporary byte array
                //
                Encoding enc_default = Encoding.Default;
                byte[] input = enc_default.GetBytes(textToEncrypt);

                // 
                // Output byte array
                //
                byte[] output = new byte[input.Length];

                //
                // Local copy of m_nBoxLen
                //
                byte[] n_LocBox = new byte[m_nBoxLen];
                m_nBox.CopyTo(n_LocBox, 0);

                //
                //	Len of Chipher
                //
                long ChipherLen = input.Length + 1;

                //
                // Run Alghoritm
                //
                for (long offset = 0; offset < input.Length; offset++)
                {
                    i = (i + 1) % m_nBoxLen;
                    j = (j + n_LocBox[i]) % m_nBoxLen;
                    byte temp = n_LocBox[i];
                    n_LocBox[i] = n_LocBox[j];
                    n_LocBox[j] = temp;
                    byte a = input[offset];
                    byte b = n_LocBox[(n_LocBox[i] + n_LocBox[j]) % m_nBoxLen];
                    output[offset] = (byte)((int)a ^ (int)b);
                }

                //
                // Put result into output string ( CryptedText )
                //
                char[] outarrchar = new char[enc_default.GetCharCount(output, 0, output.Length)];
                enc_default.GetChars(output, 0, output.Length, outarrchar, 0);
                #endregion

                response = new string(outarrchar);
            }
            catch
            {
            }

            return response;
        }
        /// <summary>
        /// Decrypting using RC2.
        /// </summary>
        /// <param name="textToDecrypt">Text to be decrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Decrypted text.
        /// </returns>
        private static string Decrypt_RC4(string textToDecrypt, string key)
        {
            string response = string.Empty;

            try
            {
                response = Encrypt_RC4(textToDecrypt, key);
            }
            catch
            {
            }

            return response;
        }
        #endregion

        #region  AES_128
        /// <summary>
        /// Encrypting using AES_128.
        /// </summary>
        /// <param name="textToEncrypt">Text to be encrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Encrypted text.
        /// </returns>
        private static string Encrypt_AES_128(string textToEncrypt, string key)
        {
            string response = string.Empty;

            try
            {
                // Plain Text to be encrypted
                byte[] PlainText = System.Text.Encoding.Unicode.GetBytes(textToEncrypt);

                StringBuilder sb = new StringBuilder();
                sb.Append(key);

                // Generate the Salt, with any custom logic and using the above string
                StringBuilder _sbSalt = new StringBuilder();
                for (int i = 0; i < 8; i++)
                {
                    _sbSalt.Append("," + sb.Length.ToString());
                }
                byte[] Salt = Encoding.ASCII.GetBytes(_sbSalt.ToString());

                // Key generation:- default iterations is 1000 and recomended is 10000
                Rfc2898DeriveBytes pwdGen = new Rfc2898DeriveBytes(sb.ToString(), Salt, 10000);

                // The default key size for RijndaelManaged is 128 bits, while the default blocksize is 128 bits.
                RijndaelManaged _RijndaelManaged = new RijndaelManaged();
                _RijndaelManaged.BlockSize = 128; // Increased it to 128 bits- min and less secure

                byte[] keyAES = pwdGen.GetBytes(_RijndaelManaged.KeySize / 8);   // This will generate a 128 bits key
                byte[] iv = pwdGen.GetBytes(_RijndaelManaged.BlockSize / 8);  // This will generate a 128 bits IV

                // On a given instance of Rfc2898DeriveBytes class,
                // GetBytes() will always return unique byte array.
                _RijndaelManaged.Key = keyAES;
                _RijndaelManaged.IV = iv;

                // Now encrypt
                byte[] cipherText2 = null;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, _RijndaelManaged.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(PlainText, 0, PlainText.Length);
                    }
                    cipherText2 = ms.ToArray();
                }

                response = Convert.ToBase64String(cipherText2);
            }
            catch
            {
            }

            return response;
        }
        /// <summary>
        /// Decrypting using AES_128.
        /// </summary>
        /// <param name="textToDecrypt">Text to be decrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Decrypted text.
        /// </returns>
        private static string Decrypt_AES_128(string textToDecrypt, string key)
        {
            string response = string.Empty;

            try
            {
                byte[] cipherText2 = Convert.FromBase64String(textToDecrypt);

                StringBuilder sb = new StringBuilder();
                sb.Append(key);

                //Generate the Salt, with any custom logic and using the above string
                StringBuilder _sbSalt = new StringBuilder();
                for (int i = 0; i < 8; i++)
                {
                    _sbSalt.Append("," + sb.Length.ToString());
                }
                byte[] Salt = Encoding.ASCII.GetBytes(_sbSalt.ToString());

                // Key generation:- default iterations is 1000 and recomended is 10000
                Rfc2898DeriveBytes pwdGen = new Rfc2898DeriveBytes(sb.ToString(), Salt, 10000);

                // The default key size for RijndaelManaged is 128 bits, while the default blocksize is 128 bits.
                RijndaelManaged _RijndaelManaged = new RijndaelManaged();
                _RijndaelManaged.BlockSize = 128; // Increase it to 128 bits- less secure

                byte[] keyAES = pwdGen.GetBytes(_RijndaelManaged.KeySize / 8);   // This will generate a 128 bits key
                byte[] iv = pwdGen.GetBytes(_RijndaelManaged.BlockSize / 8);  // This will generate a 128 bits IV

                // On a given instance of Rfc2898DeriveBytes class,
                // GetBytes() will always return unique byte array.
                _RijndaelManaged.Key = keyAES;
                _RijndaelManaged.IV = iv;

                // Now decrypt
                byte[] plainText2 = null;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, _RijndaelManaged.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherText2, 0, cipherText2.Length);
                    }
                    plainText2 = ms.ToArray();
                }

                // Decrypted text
                response = System.Text.Encoding.Unicode.GetString(plainText2);
            }
            catch
            {
            }

            return response;
        }
        #endregion

        #region  AES_192
        /// <summary>
        /// Encrypting using AES_192.
        /// </summary>
        /// <param name="textToEncrypt">Text to be encrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Encrypted text.
        /// </returns>
        private static string Encrypt_AES_192(string textToEncrypt, string key)
        {
            string response = string.Empty;

            try
            {
                // Plain Text to be encrypted
                byte[] PlainText = System.Text.Encoding.Unicode.GetBytes(textToEncrypt);

                StringBuilder sb = new StringBuilder();
                sb.Append(key);

                // Generate the Salt, with any custom logic and using the above string
                StringBuilder _sbSalt = new StringBuilder();
                for (int i = 0; i < 8; i++)
                {
                    _sbSalt.Append("," + sb.Length.ToString());
                }
                byte[] Salt = Encoding.ASCII.GetBytes(_sbSalt.ToString());

                // Key generation:- default iterations is 1000 and recomended is 10000
                Rfc2898DeriveBytes pwdGen = new Rfc2898DeriveBytes(sb.ToString(), Salt, 10000);

                // The default key size for RijndaelManaged is 256 bits, while the default blocksize is 128 bits.
                RijndaelManaged _RijndaelManaged = new RijndaelManaged();
                _RijndaelManaged.BlockSize = 192; // Increased it to 192 bits

                byte[] keyAES = pwdGen.GetBytes(_RijndaelManaged.KeySize / 8);   // This will generate a 192 bits key
                byte[] iv = pwdGen.GetBytes(_RijndaelManaged.BlockSize / 8);  // This will generate a 192 bits IV

                // On a given instance of Rfc2898DeriveBytes class,
                // GetBytes() will always return unique byte array.
                _RijndaelManaged.Key = keyAES;
                _RijndaelManaged.IV = iv;

                // Now encrypt
                byte[] cipherText2 = null;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, _RijndaelManaged.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(PlainText, 0, PlainText.Length);
                    }
                    cipherText2 = ms.ToArray();
                }

                response = Convert.ToBase64String(cipherText2);
            }
            catch
            {
            }

            return response;
        }
        /// <summary>
        /// Decrypting using AES_192.
        /// </summary>
        /// <param name="textToDecrypt">Text to be decrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Decrypted text.
        /// </returns>
        private static string Decrypt_AES_192(string textToDecrypt, string key)
        {
            string response = string.Empty;

            try
            {
                byte[] cipherText2 = Convert.FromBase64String(textToDecrypt);

                StringBuilder sb = new StringBuilder();
                sb.Append(key);

                //Generate the Salt, with any custom logic and using the above string
                StringBuilder _sbSalt = new StringBuilder();
                for (int i = 0; i < 8; i++)
                {
                    _sbSalt.Append("," + sb.Length.ToString());
                }
                byte[] Salt = Encoding.ASCII.GetBytes(_sbSalt.ToString());

                // Key generation:- default iterations is 1000 and recomended is 10000
                Rfc2898DeriveBytes pwdGen = new Rfc2898DeriveBytes(sb.ToString(), Salt, 10000);

                // The default key size for RijndaelManaged is 192 bits, while the default blocksize is 128 bits.
                RijndaelManaged _RijndaelManaged = new RijndaelManaged();
                _RijndaelManaged.BlockSize = 192; // Increase it to 192 bits

                byte[] keyAES = pwdGen.GetBytes(_RijndaelManaged.KeySize / 8);   // This will generate a 192 bits key
                byte[] iv = pwdGen.GetBytes(_RijndaelManaged.BlockSize / 8);  // This will generate a 192 bits IV

                // On a given instance of Rfc2898DeriveBytes class,
                // GetBytes() will always return unique byte array.
                _RijndaelManaged.Key = keyAES;
                _RijndaelManaged.IV = iv;

                // Now decrypt
                byte[] plainText2 = null;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, _RijndaelManaged.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherText2, 0, cipherText2.Length);
                    }
                    plainText2 = ms.ToArray();
                }

                // Decrypted text
                response = System.Text.Encoding.Unicode.GetString(plainText2);
            }
            catch
            {
            }

            return response;
        }
        #endregion

        #region  AES_256
        /// <summary>
        /// Encrypting using AES_256.
        /// </summary>
        /// <param name="textToEncrypt">Text to be encrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Encrypted text.
        /// </returns>
        private static string Encrypt_AES_256(string textToEncrypt, string key)
        {
            string response = string.Empty;

            try
            {
                // Plain Text to be encrypted
                byte[] PlainText = System.Text.Encoding.Unicode.GetBytes(textToEncrypt);

                StringBuilder sb = new StringBuilder();
                sb.Append(key);

                // Generate the Salt, with any custom logic and using the above string
                StringBuilder _sbSalt = new StringBuilder();
                for (int i = 0; i < 8; i++)
                {
                    _sbSalt.Append("," + sb.Length.ToString());
                }
                byte[] Salt = Encoding.ASCII.GetBytes(_sbSalt.ToString());

                // Key generation:- default iterations is 1000 and recomended is 10000
                Rfc2898DeriveBytes pwdGen = new Rfc2898DeriveBytes(sb.ToString(), Salt, 10000);

                // The default key size for RijndaelManaged is 256 bits, while the default blocksize is 128 bits.
                RijndaelManaged _RijndaelManaged = new RijndaelManaged();
                _RijndaelManaged.BlockSize = 256; // Increased it to 256 bits- max and more secure

                byte[] keyAES = pwdGen.GetBytes(_RijndaelManaged.KeySize / 8);   // This will generate a 256 bits key
                byte[] iv = pwdGen.GetBytes(_RijndaelManaged.BlockSize / 8);  // This will generate a 256 bits IV

                // On a given instance of Rfc2898DeriveBytes class,
                // GetBytes() will always return unique byte array.
                _RijndaelManaged.Key = keyAES;
                _RijndaelManaged.IV = iv;

                // Now encrypt
                byte[] cipherText2 = null;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, _RijndaelManaged.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(PlainText, 0, PlainText.Length);
                    }
                    cipherText2 = ms.ToArray();
                }

                response = Convert.ToBase64String(cipherText2);
            }
            catch
            {
            }

            return response;
        }
        /// <summary>
        /// Decrypting using AES_256.
        /// </summary>
        /// <param name="textToDecrypt">Text to be decrypted.</param>
        /// <param name="key">Key to be used.</param>
        /// <returns>
        ///    (string) Decrypted text.
        /// </returns>
        private static string Decrypt_AES_256(string textToDecrypt, string key)
        {
            string response = string.Empty;

            try
            {
                byte[] cipherText2 = Convert.FromBase64String(textToDecrypt);

                StringBuilder sb = new StringBuilder();
                sb.Append(key);

                //Generate the Salt, with any custom logic and using the above string
                StringBuilder _sbSalt = new StringBuilder();
                for (int i = 0; i < 8; i++)
                {
                    _sbSalt.Append("," + sb.Length.ToString());
                }
                byte[] Salt = Encoding.ASCII.GetBytes(_sbSalt.ToString());

                // Key generation:- default iterations is 1000 and recomended is 10000
                Rfc2898DeriveBytes pwdGen = new Rfc2898DeriveBytes(sb.ToString(), Salt, 10000);

                // The default key size for RijndaelManaged is 256 bits, while the default blocksize is 128 bits.
                RijndaelManaged _RijndaelManaged = new RijndaelManaged();
                _RijndaelManaged.BlockSize = 256; // Increase it to 256 bits- more secure

                byte[] keyAES = pwdGen.GetBytes(_RijndaelManaged.KeySize / 8);   // This will generate a 256 bits key
                byte[] iv = pwdGen.GetBytes(_RijndaelManaged.BlockSize / 8);  // This will generate a 256 bits IV

                // On a given instance of Rfc2898DeriveBytes class,
                // GetBytes() will always return unique byte array.
                _RijndaelManaged.Key = keyAES;
                _RijndaelManaged.IV = iv;

                // Now decrypt
                byte[] plainText2 = null;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, _RijndaelManaged.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherText2, 0, cipherText2.Length);
                    }
                    plainText2 = ms.ToArray();
                }

                // Decrypted text
                response = System.Text.Encoding.Unicode.GetString(plainText2);
            }
            catch
            {
            }

            return response;
        }
        #endregion
        #endregion

        #region NON-Standard Algorithms
        // TODO -- EMI
        private static string Encrypt_EMI(string textToEncrypt, string key)
        {
            string response = string.Empty;

            return response;
        }
        private static string Decrypt_EMI(string textToDecrypt, string key)
        {
            string response = string.Empty;

            return response;
        }
        
        // 
        // http://www.7sabores.com/blog/encriptar-datos-algoritmo-rijndael-net
        // 
        public static object Encode(object pObject)
        {
            // Preparing the algorithm
            Rijndael rijndael = Rijndael.Create();

            // getting Key1 and Key2
            object vlKey = rijndael.Key;
            object vlIV = rijndael.IV;

            //Usamos el algoritmo
            using (rijndael)
            {
                object vlEncrypted = EncryptObjectToBytes(pObject, rijndael.Key, rijndael.IV);

                // Encrypted object
                string[] vlEnEncrypted = ((IEnumerable)vlEncrypted).Cast<object>()
                    .Select(x => x.ToString())
                    .ToArray();

                // Using key1
                string[] vlEnKey = ((IEnumerable)vlKey).Cast<object>()
                    .Select(x => x.ToString())
                    .ToArray();

                // Using Key2
                string[] vlEnIV = ((IEnumerable)vlIV).Cast<object>()
                    .Select(x => x.ToString())
                    .ToArray();

                // Converting the encrypted to string
                string vlValueEncode = string.Empty;
                vlValueEncode = vlValueEncode + string.Join(",", vlEnEncrypted);
                vlValueEncode = vlValueEncode + "/" + string.Join(",", vlEnKey);
                vlValueEncode = vlValueEncode + "/" + string.Join(",", vlEnIV);

                // String to Object
                object vlValueFinal = vlValueEncode;

                return vlValueFinal;
            }
        }
        private static byte[] EncryptObjectToBytes(object pObject, byte[] pKey, byte[] pIV)
        {
            // Checking if we have parameters or they are null
            if (pObject == null)
            {
                throw new ArgumentNullException();
            }
            if (pKey == null || pKey.Length <= 0)
            {
                throw new ArgumentNullException();
            }
            if (pIV == null || pIV.Length <= 0)
            {
                throw new ArgumentNullException();
            }

            // Preparing the object to get ehe encrypted object
            byte[] encrypted;

            // Creating the algorithm
            Rijndael rijndael = Rijndael.Create();

            // Using the algorithm
            using (rijndael)
            {
                // Using Key1 and Key2
                rijndael.Key = pKey;
                rijndael.IV = pIV;

                // Creating encrypter
                ICryptoTransform encryptor = rijndael.CreateEncryptor(rijndael.Key, rijndael.IV);

                // Preparing streams
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            // Writting data ...
                            swEncrypt.Write(pObject);
                        }

                        // Storing the object
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Giving the result
            return encrypted;
        }

        public static object Decode(byte[] pEncode, byte[] pKey, byte[] pIV)
        {
            object vlValue = DecryptObjectFromBytes(pEncode, pKey, pIV);

            // Checking if it's null
            if (vlValue != null)
            {
                return vlValue;
            }
            return null;
        }
        private static object DecryptObjectFromBytes(byte[] pObject, byte[] pKey, byte[] pIV)
        {
            // Checking if parameters are null
            if (pObject == null || pObject.Length <= 0)
            {
                throw new ArgumentNullException();
            }
            if (pKey == null || pKey.Length <= 0)
            {
                throw new ArgumentNullException();
            }
            if (pIV == null || pIV.Length <= 0)
            {
                throw new ArgumentNullException();
            }

            // Storing encrypted object
            object vlDecodeObject = null;

            // Creating the algorithm
            Rijndael rijndael = Rijndael.Create();

            // Using the algorithm
            using (rijndael)
            {
                // Giving Key1 and Key2
                rijndael.Key = pKey;
                rijndael.IV = pIV;

                // Creating the decrypter
                ICryptoTransform decryptor = rijndael.CreateDecryptor(rijndael.Key, rijndael.IV);

                // Using streams
                using (MemoryStream msDecrypt = new MemoryStream(pObject))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Writting values on the object
                            vlDecodeObject = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            // Returning the result
            return vlDecodeObject;
        }
        #endregion
        #endregion
    }
}
