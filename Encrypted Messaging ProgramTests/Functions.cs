using System;
using System.Collections.Generic;
using System.Text;

namespace Encrypted_Messaging_Program
{
    static class Functions
    {   // Encrypt + Decrypt Test
        public static string ByteArrToHex(Byte[] result)
        {
            return BitConverter.ToString(result).Replace("-", String.Empty);
        }
        public static byte[] HexToByteArr(string hex)
        {
            byte[] b_hex = new byte[hex.Length / 2];
            int x = 0;
            for (int i = 0; i < hex.Length; i += 2)
            {
                int d_hex = Convert.ToInt32(hex.Substring(i, 2), 16);
                b_hex[x] = Convert.ToByte(d_hex);
                x++;
            }
            return b_hex;
        }
        public static string WordArrToString(Byte[,] words)
        {
            string[] result = new string[words.GetLength(0)];
            for (int i = 0; i < words.GetLength(0); i++)
            {
                result[i] = ByteArrToString(new byte[] { words[i, 0], words[i, 1], words[i, 2], words[i, 3] });
            }
            return string.Join("", result).ToLower();
        }
        public static string ByteArrToString(Byte[] result)
        {
            return BitConverter.ToString(result).Replace("-", String.Empty);
        }
        // Encrypt->Decrypt Test
        public static byte[] UnicodeToByteArr(string unicode)
        {
            return Encoding.Unicode.GetBytes(unicode);
        }
        public static string ByteArrToBase64(Byte[] result)
        {
            return Convert.ToBase64String(result);
        }
        public static byte[] Base64ToByteArr(string base64)
        {
            return Convert.FromBase64String(base64);
        }
    }
}
