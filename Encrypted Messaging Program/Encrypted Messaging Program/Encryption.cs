using Firebase.Database;
using Firebase.Database.Query;
using System;
using System.Text;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Linq;
using System.Reactive.Linq;






namespace Encryption_Prototype
{
    public class KeyData
    {
        public BigInteger prime { get; set; }
        public int global { get; set; }
        public BigInteger A_Key { get; set; }
        public BigInteger B_Key { get; set; }
        public KeyData(BigInteger p, int g, BigInteger secret, int userNum)
        {
            prime = p;
            global = g;
            if (userNum == 0) { A_Key = secret; }
            else { B_Key = secret; }
        }
        public String output()
        {
            return $"Prime: {prime}\nGlobal: {global}\nA Key: {A_Key}\nB Key: {B_Key}";
        }
    }

    public class DiffieHellman
    {
        private BigInteger prime;
        private int global;
        private BigInteger userKey;

        int user;
        bool debug;
        char p_char;

        private RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();

        private int[] identifiers = { 5, 14, 15, 16, 17, 18 };
        private string[] primes =  {
            "0FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
            "0FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
            "0FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
            "0FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
            "0FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF",
            "0FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF"
        };

        public DiffieHellman(int secret_size = 256, bool p_debug = false, char player_char = '\0')   // (Both users) Generates user secret
        { 
            // Create user secret
            byte[] b_secret = new byte[secret_size];
            rngCsp.GetBytes(b_secret);
            userKey = BitConverter.ToUInt32(b_secret, 0);

            debug = p_debug; p_char = player_char;
            if (debug) { Console.WriteLine($"User {p_char} Secret Key: {userKey}"); }
        }

        public KeyData Initilise(int p_id=14, int g = 5)                                             // (First user) Initilise Prime and Global values  |  Calculate their public key- A
        {
            // Prime (p): 
            prime = getPrime(p_id);

            //Base (g):
            global = g;

            //A: Calculate public key
            BigInteger publicKey = getPublicKey();
            user = 0;

            if (debug){
                Console.WriteLine($"\n---Initilise--     (User {p_char})");
                Console.WriteLine($"Prime(p): {prime.ToByteArray().Length} bytes");
                Console.WriteLine($"Base(g): {g}");
                Console.WriteLine($"User {p_char} Public Key: {publicKey.ToString("X")}");
            }

            return new KeyData(prime, g, publicKey, 0);
        }

        public KeyData Respond(KeyData data)                                                         // (Second user) Use values to calculate their public key- B
        {
            prime = data.prime;
            global = data.global;
            BigInteger publicKey = getPublicKey();
            user = 1;
            data.B_Key = publicKey;

            if (debug) {
                Console.WriteLine($"\n---Respond---   (User {p_char})");
                Console.WriteLine("Defined public variables");
                Console.WriteLine($"User {p_char} Public Key: {publicKey.ToString("X")}");
            }

            return data;
        }

        public BigInteger getSharedKey(KeyData data)                                                 // (Both users) Calculate Shared Master Key:  User 1: B^a  mod  p | User 2: A^b  mod  p
        {
            BigInteger request_secret;
            if (user == 0) { request_secret = data.B_Key; }
            else { request_secret = data.A_Key;  }

            BigInteger sharedKey = BigInteger.ModPow(request_secret, userKey, prime);
            if (debug) { Console.WriteLine($"Shared Key calculated by {p_char}: {sharedKey}"); }

            return sharedKey;
        }

        private BigInteger getPrime(int p_id)    // [Get required prime from array]
        {
            int prime_num = Array.IndexOf(identifiers, p_id);
            if (prime_num == -1) { prime_num = 1; }

            return BigInteger.Parse(primes[prime_num], System.Globalization.NumberStyles.AllowHexSpecifier);
        }

        private BigInteger getPublicKey()        // [Calculate public key - g^(a/b) mod p]
        {
            BigInteger publicKey = BigInteger.ModPow(global, userKey, prime);
            return publicKey;
        }
        
        public void setPrivateKey(BigInteger newKey)  // TEST ONLY
        {  userKey = newKey;  }
    }

    public class AES
    {                   // Bytes:   16   24   32 
        public int[] lengths  =  { 128, 192, 256 };
        public int[] rounds =    { 10, 12, 14 };
        public int keyIndex;     // 0,1,2
        public int keyLength;    // Length of key in bits: 128, 192, 256
        public int b_keyLength;  // Length of key in bytes: 16, 24, 32
        public int keyRounds;    // Number of rounds for key: 10, 12, 14
        public int wordsPerRound; // Number of words required for each round:  4, 6, 8

        private int[,] s_box = // Box used for g() in Key Schedule and SubBytes
        {   // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, // 0
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, // 1
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, // 2
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, // 3
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, // 4
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, // 5
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, // 6
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, // 7
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, // 8
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, // 9
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, // A
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, // B
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, // C
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, // D
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, // E
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}  // F
        };

        public bool b_debug;
        public string b_debug_type; // 64, hex, bin
        //public string[] debug_Blacklist = new string[] { "ScheduleKey", "ScheduleFunction" };
        public string[] debug_Blacklist = new string[] { };

        //debug_methodBlacklist = new string[] { "ScheduleKey", "ScheduleFunction" };




        public AES(int level=192, bool p_debug=false, string debug_type = "64") // Constructor
        {
            keyIndex = Array.IndexOf(lengths, level);
            if(keyIndex == -1) { keyIndex = 1; }

            keyLength = lengths[keyIndex];
            b_keyLength = keyLength / 8;
            keyRounds = rounds[keyIndex];
            wordsPerRound = b_keyLength / 4; ;


            b_debug = p_debug;
            b_debug_type = debug_type;
            debug($"Initilised AES({level}):\n    Key Index = {keyIndex}\n    Key Length = {keyLength}\n    Byte Key Length = {b_keyLength}\n    Key Rounds = {keyRounds}\n--------\n");
        }

        // Main Encrypt Functions
        public byte[] Encrypt( string s_key, string message)
        {
            // Hex Key -> Byte Key
            int x=0;
            byte[] sharedKey = new byte[s_key.Length / 2];
            for (int i=0; i< s_key.Length; i += 2)
            {
                int d_key = Convert.ToInt32(s_key.Substring(i, 2), 16);
                sharedKey[x] = Convert.ToByte(d_key);
                x++;
            }


            // Resize key
            if (sharedKey.Length < b_keyLength)
            {
                debug("Error: Shared Key is too small");
                return new byte[0];
            }
            else if (sharedKey.Length > b_keyLength)
            {
                debug($"Decreased Shared Key size ({sharedKey.Length}->{b_keyLength})");
                sharedKey = SHA256.Create().ComputeHash(sharedKey);
                Array.Resize(ref sharedKey, b_keyLength);
                debug($"New Key:  {ConvertByteArr(sharedKey)}");
            }

            // Enlarge key
            Byte[,] l_sharedKey = ScheduleKey(sharedKey);

            // Convert message to 128-bit blocks
            byte[] b_message = Encoding.Unicode.GetBytes(message);

            byte[] cipher = new byte[b_message.Length];
            int cipher_pos = 0;
            byte[] message_128 = new byte[16];
            byte[] result = new byte[16];

            debug($"The message is {b_message.GetLength(0)} bytes long");

            for (int i=0; i < b_message.GetLength(0); i++){
                message_128[i % 16] = b_message[i]; //(i / 128 + 1) * i
                if(i % 16 == 15){
                    debug($"128-bit message number {i / 16}: {ConvertByteArr(message_128)}", true);
                    result = EncryptByte(l_sharedKey, message_128);

                    cipher = cipher.Concat(result).ToArray();
                    //for(int j=0; j < result.Length; j++)
                    //{
                        //cipher[cipher_pos] = result[j];
                        //cipher_pos++;
                    //}
                    message_128 = new byte[16];
                }
            }
            debug($"128-bit message number {cipher.Length / 128}: {ConvertByteArr(message_128)}", true);
            result = EncryptByte(l_sharedKey, message_128);
            cipher = cipher.Concat(result).ToArray();


            return cipher;
        }
        
        private byte[] EncryptByte(byte[,] p_sharedKey, byte[] message) // Main Encryption Method
        {
            byte[,] sharedKey = p_sharedKey;
            //tex: $$\text{msg}\  \otimes [w_0,w_1,w_2,w_3]\ \ \ \ \  \small(192\rightarrow w_5, 256\rightarrow w_7)$$
            byte[] firstBytes = new byte[wordsPerRound * 4];
            for(int i=0; i<wordsPerRound; i++)
            {
                byte[] currentWord = getWord(p_sharedKey, i);
                for(int j=0;j < 4; j++)
                {
                    firstBytes[(4 * i) + j] = currentWord[j];
                }
                //firstBytes = firstBytes.Concat().ToArray();
            }
            debug($"  FirstBytes: {ConvertByteArr(firstBytes)}", true);
            byte[] oldmessage = (byte[])message.Clone();
            message = ByteXOR(message, firstBytes);
            debug($"{ConvertByteArr(oldmessage)} XOR {ConvertByteArr(firstBytes)} -> {ConvertByteArr(message)}");
            for(int roundNum=0; roundNum < keyRounds; roundNum++){
                oldmessage = (byte[])message.Clone();
                SubBytes(ref message);
                debug($"  Substitute: {ConvertByteArr(oldmessage)} -> {ConvertByteArr(message)}");
                debug($"Number of words: {message.Length / 4}");

            }

            return message;
        }


        // --- Schedule ---
        public Byte[,] ScheduleKey(Byte[] sharedKey)                  // Calculates + splits the keys for the encryption ahead
        {
            Byte[,] Words = new byte[((wordsPerRound) + (4 * keyRounds)), 4];   // Length of words: [44, 54, 64] - (Note that not all are required)   
            debug($"\n   Schedule Key\n-Created Words array (length: {Words.GetLength(0)}x{Words.GetLength(1)})");

            //tex:   HeadWord = First Word of each 4-word set ($i_0,i_4,i_8$)
            Byte[] LastHeadWord = new byte[4];
            Byte[] PreviousWord = new byte[4];

            //tex: Key for Round 0: Split key into 4/6/8 words
            //$$\{w_0, w_1,w_2,w_3\}\ \ \text{  (for 128)}$$
            for (int i=0; i< (wordsPerRound); i++){
                for(int j=0; j<4; j++){
                    Words[i, j] = sharedKey[(4 * i) + j];
                }
            }
            debug($"\n-Split key into {wordsPerRound} words for round 0:");
            debug(OutputWordArr(Words), true);

            LastHeadWord = getWord(Words, 3);
            PreviousWord = getWord(Words, wordsPerRound-1);

            int Rcon = 1; // Round Constant
            int currentWordNum = wordsPerRound;

            // Keys for next Rounds: 4 words each
            for (int i=1; i<= keyRounds; i++) //
            {
                debug($"\nKey Schedule Round {i} \nw{currentWordNum}-Generate headword (word 0)"); // Current Word = i*(wordsPerRound)
                // Generate next head word

                //tex:$$w_{i+4}=w_i\otimes g(w_{i+3})$$

                Byte[] g_Previous = ScheduleFunction(  (byte[]) PreviousWord.Clone(), i); //  g(lastWord)

                Byte[] XOR_Result = ByteXOR(g_Previous, getWord(Words, currentWordNum- wordsPerRound));
                debug($"    {ConvertByteArr(g_Previous)} XOR {ConvertByteArr(getWord(Words, currentWordNum - wordsPerRound))} -> {ConvertByteArr(XOR_Result)}");

                PreviousWord = SetWord(XOR_Result, i * wordsPerRound, Words);
                LastHeadWord = XOR_Result;
                currentWordNum++;
                if (Words.GetLength(0) == currentWordNum)
                {
                    Console.WriteLine("Reached end!!!");
                    break;
                }
                //else { Console.WriteLine(currentWordNum); }

                // Generate other 3/5/7 words
                //tex:$$w_{i+5}=w_{i+4}\otimes w_{i+1}\\w_{i+6}=w_{i+5}\otimes w_{i+2}\\w_{i+7}=w_{i+6}\otimes w_{i+3}$$
                for (int j=1; j< (wordsPerRound); j++)
                {
                    debug($"w{currentWordNum}-Generate word {j}");

                    if(keyLength == 256 && j == 4) { 
                        //Console.WriteLine("")
                        byte[] OldWord = (byte[]) PreviousWord.Clone();
                        SubBytes(ref PreviousWord);
                        debug($"    Substitute: {ConvertByteArr(OldWord)}->{ConvertByteArr(PreviousWord)}");
                    }

                    XOR_Result = ByteXOR( PreviousWord , getWord(Words, ((i-1) * (wordsPerRound)) + j));
                    debug($"    {ConvertByteArr(PreviousWord)} XOR {ConvertByteArr(getWord(Words, ((i-1)* (wordsPerRound)) +j))} -> {ConvertByteArr(XOR_Result)} (w{currentWordNum - 1} XOR w{currentWordNum- wordsPerRound})");
                    
                    PreviousWord = SetWord(XOR_Result, currentWordNum, Words);
                    currentWordNum++;
                    if (Words.GetLength(0) == currentWordNum){ break; }
                    //else { Console.WriteLine(Words.GetLength(0) ); }
                }
                if (Words.GetLength(0) == currentWordNum){break;}
            }

            debug(OutputWordArr(Words, true), true);
            return Words;
        } 

        private Byte[] ScheduleFunction(Byte[] Word, int RoundNum)  // return Byte
        {
            //tex:$w_{i+4}=w_i\otimes g(w_{i+3})$
            //$$g(w_{i+3})\rightarrow S\Big( LeftShift(w_{i+3})\Big)\otimes [RC(i), 00, 00, 00]$$
            Byte[] oldWord = (Byte[]) Word.Clone();

            //tex: One-byte left circular roation
            //$$[b_0,b_1, b_2, b_3]\Rightarrow [b_1,b_2,b_3,b_0]$$
            LeftShift(ref Word);
            debug($"    Left Shift: {ConvertByteArr(oldWord)}->{ConvertByteArr(Word)}");
            oldWord = (Byte[])Word.Clone();

            //tex: Byte Substitution for each byte of the word using the S-Box:
            // $$[b_1,b_2,b_3,b_0] \Rightarrow [S(b_1),\ S(b_2),\ S(b_3)]$$
            SubBytes(ref Word);
            debug($"    Substitute: {ConvertByteArr(oldWord)}->{ConvertByteArr(Word)}");
            oldWord = (Byte[])Word.Clone();
            byte RoundConstant = RConst(RoundNum);
            Word = new byte[] { (byte) (RoundConstant ^ Word[0]), Word[1], Word[2], Word[3] };
            debug($"    {ConvertByteArr(oldWord)} XOR {ConvertByteArr(new byte[] {RoundConstant})} -> {ConvertByteArr(Word)} ");
            return Word;
        }
        public byte RConst(int num)
        {
            int result = 1;
            for (int i = 1; i < num; i++)
            {
                result = 2 * result;
                if (result > 0x80)
                {
                    result = result ^ 0x11B;
                }
            }
            //Console.WriteLine($"Round Const {num} = {result}");
            return (byte)result;
        }

        
        public byte[] LeftShift(ref byte[] Word)
        {
            byte temp = Word[0];
            for (int i=0; i<Word.Length-1; i++)
            {
                Word[i] = Word[i + 1];
            }
            Word[Word.Length - 1] = temp;

            return Word;
        }

       
        
        // General Functions
        private Byte[] getWord(Byte[,] Words, int index) // Gets the word at index
        {
            Byte[] Word = new byte[4];
            for (int j=0; j < 4; j++)
            {
                Word[j] = Words[index, j];
            }
            return Word;
        }

        private Byte[] SubBytes(ref Byte[] Word) // Substitute each byte of the word using the S-Box
        {
            Byte[] OldWord = (Byte[]) Word.Clone();
            for(int i=0; i<Word.Length; i++)
            {
                int x = (Word[i] & 0xF0) >> 4;
                int y = Word[i] & 0x0F;
                //Console.WriteLine($"x: {x}   y: {y}");
                Word[i] = (byte) s_box[x,y];
                
            }
            //debug($"Substituted {ConvertByteArr(OldWord)} for {ConvertByteArr(Word)}");
            return Word;
        }

        private string OutputWordArr(Byte[,] key, bool showEmpty = false)
        {
            string output = "";
            for (int i=0; i<key.GetLength(0); i++)
            {
                Byte[] row = new byte[key.GetLength(1)];
                bool empty = true;
                for (int j=0; j < key.GetLength(1); j++)
                {
                    //Console.WriteLine($"i:{i}; j:{j}");
                    row[j] = key[i, j];
                    if(key[i,j].ToString() != "0"){
                        empty = false;
                    }
                }
                if(!empty){
                    string s_row = ConvertByteArr(row);
                    output = output + $"w{i}: {s_row.Substring(0, s_row.Length)}" + "\n";
                }
                else if (showEmpty) { output += "-\n"; }
            }
            return output;
        }
        private Byte[] SetWord(Byte[] Word, int index, Byte[,] Words)
        {
            //Console.WriteLine(Words.GetLength(0));
            for (int i = 0; i < Words.GetLength(1); i++){
                Words[index, i] = Word[i];
                //Console.WriteLine($"{index}, {i}");
            }
            return Word;
        }
        private Byte[] ByteXOR(Byte[] Word1, Byte[] Word2)
        {
            if(Word1.Length != Word2.Length) { debug($"Invalid bytes given {Word1.Length} vs {Word2.Length}"); return new byte[4]; }
            Byte[] result = new byte[Word1.Length];
            for (int i = 0; i < Word1.Length; i++)
            {
                result[i] = (byte) (Word1[i] ^ Word2[i]);
            }
            return result;
        }
        private string ConvertByteArr(Byte[] data)
        {
            string text = "";
            if (b_debug_type == "64")
            {
                text = Convert.ToBase64String(data);
            }
            else if(b_debug_type == "hex")  // Hex
            {
                //BigInteger num = BitConverter.ToInt32(data);
                //text = num.ToString("X");
                text = BitConverter.ToString(data).Replace('-', '\0');
                //text = String.Join(String.Empty, BitConverter.ToString(data).Split('-').Reverse());
            }
            else
            { 
                foreach(byte b_data in data)
                {
                    text = text + Convert.ToString(b_data, 2).PadLeft(8, '0') + " ";
                }
            }
            return text;
        }
        private void debug(string message, bool ignoreConcat=false)
        {
            string method = (new System.Diagnostics.StackTrace()).GetFrame(1).GetMethod().Name;
            if (b_debug && !debug_Blacklist.Contains(method))
            {
                if (message.Length > (Console.WindowWidth-3) && !ignoreConcat)
                {
                    message = message.Remove(Console.WindowWidth - 3) + "..."; ;
                }
                Console.WriteLine(message);
            }
        }

    }
}
