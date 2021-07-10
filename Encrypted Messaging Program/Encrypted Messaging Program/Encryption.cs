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






namespace Encrpytion_Prototype
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
        public int[] rounds =  { 10, 12, 14 };
        public int keyIndex;
        public int keyLength;
        public int b_keyLength;  // In bytes

        public bool debug;
        public AES(int level=192, bool p_debug=false)
        {
            keyIndex = Array.IndexOf(lengths, level);
            if(keyIndex != -1) { keyLength = lengths[keyIndex]; }
            else { keyLength = 192; }
            b_keyLength = keyLength / 8;
            debug = p_debug;
        }
        public byte[] Encrypt( BigInteger sharedKey, string message)
        {
            return EncryptByte(sharedKey, Encoding.ASCII.GetBytes(message));
        }

        private byte[] EncryptByte(BigInteger i_sharedKey, byte[] message)
        {
            byte[] sharedKey = i_sharedKey.ToByteArray();
            if (debug){
                Console.WriteLine($"Message:  {Convert.ToBase64String(message)}");
                Console.WriteLine($"Key:      {Convert.ToBase64String(sharedKey)}");
            }
            if (sharedKey.Length < b_keyLength)
            {
                Console.WriteLine("Error: Shared Key is too small");
                return new byte[0];
            }
            else if (sharedKey.Length > b_keyLength)
            {
                if(debug){ Console.WriteLine($"Decreased Shared Key size ({sharedKey.Length}->{b_keyLength})"); }
                //Array.Resize(ref sharedKey, b_keyLength);

                SHA256 testSHA256 = SHA256.Create();
                sharedKey = testSHA256.ComputeHash(sharedKey);
                Array.Resize(ref sharedKey, b_keyLength);
                if (debug) { Console.WriteLine($"New Key:  {Convert.ToBase64String(sharedKey)}"); }
            }

            ScheduleKey(sharedKey);

            return new byte[0];
        }
        private Byte[,] ScheduleKey(Byte[] sharedKey)
        {
            Byte[,] Words = new byte[((4 * rounds[keyIndex])+4), 4];
            Byte[] LastHeadWord = new byte[4];
            // w0 -> w3
            for (int i=0; i< (b_keyLength/4); i++){
                for(int j=0; j<4; j++){
                    Words[i, j] = sharedKey[(4 * i) + j];
                }
            }
            LastHeadWord = getWord(Words, 0);
            // Generate keys for each round:
            for (int i=1; i<=rounds[keyIndex]; i++)
            {
                //Calculate beginning
                generateNextHead(LastHeadWord); //Words[i, 0] = 
                LastHeadWord = getWord(Words, i);
            }

            OutputByteArr(Words, true);
            return Words;
        } 

        private void generateNextHead(Byte[] Word)  // return Byte
        {
            Console.WriteLine($"Previous Head: {Convert.ToBase64String(Word)}");
            LeftShift(ref Word);
            Console.WriteLine($"Left Shift: {Convert.ToBase64String(Word)}");
        }

        private Byte[] LeftShift(ref Byte[] Word)
        {
            byte temp = Word[Word.Length - 1];
            byte temp2;
            for(int i=0; i < Word.Length; i++)
            {
                temp2 = Word[i];
                Word[i] = temp;
                temp = temp2;
            }
            return Word;
        }

        private Byte[] getWord(Byte[,] Words, int index)
        {
            Byte[] Word = new byte[4];
            for (int j=0; j < Words.GetLength(1); j++)
            {
                Word[j] = Words[index, j];
            }
            return Word;
        }

        private void OutputByteArr(Byte[,] key, bool showEmpty = false)
        {
            for (int i=0; i<key.GetLength(0); i++)
            {
                Byte[] row = new byte[4];
                for (int j=0; j < key.GetLength(1); j++)
                {
                    //Console.WriteLine($"i:{i}; j:{j}");
                    row[j] = key[i, j];
                }
                string s_row = Convert.ToBase64String(row);
                if (s_row != "AAAAAA==") { Console.WriteLine(s_row.Substring(0, s_row.Length-2)); }
                else if(showEmpty) { Console.WriteLine("-"); }
            }
        }
        
    }
}
