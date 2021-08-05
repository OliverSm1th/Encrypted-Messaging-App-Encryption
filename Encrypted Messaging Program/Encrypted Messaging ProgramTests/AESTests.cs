using Microsoft.VisualStudio.TestTools.UnitTesting;
using Encryption_Prototype;
using System;

namespace AESTest
{
    [TestClass]
    public class KeyExpansionTests
    {

        [TestMethod] // The following checks uses examples from the official documentation https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf (see Apendix A)
        public void KeyExpansionA1_128()
        {
            string key = "2b7e151628aed2a6abf7158809cf4f3c";
            Byte[,] result = new AES(128).ScheduleKey(HexToByteArr(key)).value;
            string expected = "2b7e151628aed2a6abf7158809cf4f3ca0fafe1788542cb123a339392a6c7605f2c295f27a96b9435935807a7359f67f3d80477d4716fe3e1e237e446d7a883bef44a541a8525b7fb671253bdb0bad00d4d1c6f87c839d87caf2b8bc11f915bc6d88a37a110b3efddbf98641ca0093fd4e54f70e5f5fc9f384a64fb24ea6dc4fead27321b58dbad2312bf5607f8d292fac7766f319fadc2128d12941575c006ed014f9a8c9ee2589e13f0cc8b6630ca6";
            
            Assert.AreEqual(expected, WordArrToString(result), "Key Expansion Test 1 for 128 failed");
        }
        [TestMethod]
        public void KeyExpansionA2_192()
        {
            string key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
            Byte[,] result = new AES(192).ScheduleKey(HexToByteArr(key)).value;
            string expected = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7bfe0c91f72402f5a5ec12068e6c827f6b0e7a95b95c56fec24db7b4bd69b5411885a74796e92538fde75fad44bb095386485af05721efb14fa448f6d94d6dce24aa326360113b30e6a25e7ed583b1cf9a27f939436a94f767c0a69407d19da4e1ec1786eb6fa64971485f703222cb8755e26d135233f0b7b340beeb282f18a2596747d26b458c553ea7e1466c9411f1df821f750aad07d753ca4005388fcc5006282d166abc3ce7b5e98ba06f448c773c8ecc720401002202";
            Assert.AreEqual(expected, WordArrToString(result), "Key Expansion Test 2 for 192 failed");
        }
        [TestMethod]
        public void KeyExpansionA3_256()
        {
            string key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
            Byte[,] result = new AES(256).ScheduleKey(HexToByteArr(key)).value;
            string expected = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff49ba354118e6925afa51a8b5f2067fcdea8b09c1a93d194cdbe49846eb75d5b9ad59aecb85bf3c917fee94248de8ebe96b5a9328a2678a647983122292f6c79b3812c81addadf48ba24360af2fab8b46498c5bfc9bebd198e268c3ba709e0421468007bacb2df331696e939e46c518d80c814e20476a9fb8a5025c02d59c58239de1369676ccc5a71fa2563959674ee155886ca5d2e2f31d77e0af1fa27cf73c3749c47ab18501ddae2757e4f7401905acafaaae3e4d59b349adf6acebd10190dfe4890d1e6188d0b046df344706c631e";
            Assert.AreEqual(expected, WordArrToString(result), "Key Expansion Test 3 for 256 failed");
        }

        // Useful Functions:
        public Byte[] HexToByteArr(string sharedKey)
        {
            int x = 0;
            byte[] b_key = new byte[sharedKey.Length / 2];
            for (int i = 0; i < sharedKey.Length; i += 2)
            {
                int d_key = Convert.ToInt32(sharedKey.Substring(i, 2), 16);
                b_key[x] = Convert.ToByte(d_key);
                x++;
            }
            return b_key;
        }
        public string ByteArrToString(Byte[] result)
        {
            return BitConverter.ToString(result).Replace("-", String.Empty);
        }
        public string WordArrToString(Byte[,] words)
        {
            string[] result = new string[words.GetLength(0)];
            for(int i=0; i<words.GetLength(0); i++)
            {
                result[i] = ByteArrToString(new byte[] { words[i, 0], words[i, 1], words[i, 2], words[i, 3] });
            }
            return string.Join("", result).ToLower();
        }
    }
    [TestClass]
    public class EncryptionTests
    {
        [TestMethod] // From the official documentation https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf (see Apendix B+C)
        public void EncryptionB_128()
        {
            string key = "2b7e151628aed2a6abf7158809cf4f3c";
            string message = "3243f6a8885a308d313198a2e0370734";
            Byte[] result = new AES(128).Encrypt(key, message, true);

            string expected = "3925841d02dc09fbdc118597196a0b32";
            Assert.AreEqual(expected, ByteArrToHex(result).ToLower());
        }
        [TestMethod]
        public void EncryptionC_All()
        {
            string[] keys = new string[]     { "000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f1011121314151617", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" };
            string[] messages = new string[] { "00112233445566778899aabbccddeeff", "00112233445566778899aabbccddeeff"                , "00112233445566778899aabbccddeeff" };
            string[] expected = new string[] { "69c4e0d86a7b0430d8cdb78070b4c55a", "dda97ca4864cdfe06eaf70a0ec0d7191"                , "8ea2b7ca516745bfeafc49904b496089" };
            int[] types = new int[] { 128, 192, 256 };
            Byte[] result;

            for (int i=0; i<keys.Length; i++)
            {
                result = new AES(types[i]).Encrypt(keys[i], messages[i], true);
                Assert.AreEqual(expected[i], ByteArrToHex(result).ToLower(), $"Failed C{i} Encryption Test ({types[i]})");
                Console.WriteLine($"Passed C{i} Encryption Test ({types[i]})");
            }

        }

        private string ByteArrToHex(Byte[] result)
        {
            return BitConverter.ToString(result).Replace("-", String.Empty);
        }
    }
    [TestClass]
    public class DecryptionTests
    {
        [TestMethod]
        public void DecryptionB_128() // From the official documentation https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf (see Apendix B+C)
        {
            string key = "2b7e151628aed2a6abf7158809cf4f3c";
            string cipher = "3925841d02dc09fbdc118597196a0b32";
            string result = new AES(128).Decrypt(key, cipher, true);

            string expected = "3243f6a8885a308d313198a2e0370734";
            Assert.AreEqual(expected, result.ToLower());
        }
        [TestMethod]
        public void DecryptionC_All()
        {
            string[] keys = new string[] { "000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f1011121314151617", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" };
            string[] ciphers = new string[] { "69c4e0d86a7b0430d8cdb78070b4c55a", "dda97ca4864cdfe06eaf70a0ec0d7191", "8ea2b7ca516745bfeafc49904b496089" };
            string[] expected = new string[] { "00112233445566778899aabbccddeeff", "00112233445566778899aabbccddeeff", "00112233445566778899aabbccddeeff" };
            
            int[] types = new int[] { 128, 192, 256 };
            string result;

            for (int i = 0; i < keys.Length; i++)
            {
                result = new AES(types[i]).Decrypt(keys[i], ciphers[i], true);
                Assert.AreEqual(expected[i], result.ToLower(), $"Failed C{i} Decryption Test ({types[i]})");
                Console.WriteLine($"Passed C{i} Decryption Test ({types[i]})");
            }

        }
        
        
        private string ByteArrToHex(Byte[] result)
        {
            return BitConverter.ToString(result).Replace("-", String.Empty);
        }
    }
}

