using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;


namespace Encrypted_Messaging_Program
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BigInteger key = BigInteger.Parse("8793096696442703592598861102068922610554525246074204363478230198497669637684145572659610604726937016248865610002020503655972655804560233901919853989986196226498373599539879508741585808811311782881831172417458321347474152351272789007345836719044398754329833715647263955719034006553230110430130388517202315998157428787551788655332025628032090178999116769427859754522899765587607550377395732905927271157556403532999597209550341437863369720527585294659971080900003644205862798581594461200352576595299477262673387392013956913851226574415301475377435882406806475431154028167033754276006479823102221823176936645712863692488");
            int type = 192;




            AES test = new AES(type, true, "hex ");

            byte[] sharedKey = SHA256.Create().ComputeHash(key.ToByteArray());
            Array.Resize(ref sharedKey, 192 / 8);


            Console.WriteLine($"     --AES {type}--\nKey: {ByteArrToHex(sharedKey)}");



            Console.Write("Input Message: ");
            string input  = Console.ReadLine();
            Console.SetCursorPosition(0, Console.CursorTop - 1);
           

            Console.WriteLine($"Input Message: {input} ->  {ByteArrToHex(UnicodeToByteArr(input))}");

            Console.WriteLine("\n   Encryption:");

            byte[] b_encryptedMessage = test.EncryptCBC(key.ToByteArray(), UnicodeToByteArr(input), new byte[16]);

            

            string encryptedMessage = ByteArrToBase64(b_encryptedMessage);

            Console.WriteLine($"Encrypted Message: {encryptedMessage.PadRight(25)} (Hex: {ByteArrToHex(b_encryptedMessage)})");

            Console.WriteLine("\n   Decryption:");

            byte[] b_decryptedMessage = test.EncryptCBC(key.ToByteArray(), Base64ToByteArr(encryptedMessage), new byte[16], true);

            string decryptedMessage = Encoding.Unicode.GetString(b_decryptedMessage).Replace("\0", String.Empty);

            Console.WriteLine($"Decrypted Message: {decryptedMessage.PadRight(25)} (Hex: {ByteArrToHex(b_decryptedMessage)})\n");


            if (decryptedMessage == input) { Console.WriteLine("[TEST PASSED]\n\n"); }
            else { Console.WriteLine($"[TEST FAILED]\n\n"); }
            
        }

        private void testDH()
        {
            //Dictionary<string, BigInteger[]> Server = new Dictionary<string, BigInteger[]>();


            Console.WriteLine("User 1  (a)");
            DiffieHellman user1 = new DiffieHellman(128, true, 'A');
            Console.WriteLine("User 2  (b)");
            DiffieHellman user2 = new DiffieHellman(128, true, 'B');

            Console.WriteLine();

            KeyData data = user1.Initilise(5); // Send Friend Request
            //Server.Add(userID, data);
            user2.Respond(data);
            BigInteger secret2 = user2.getSharedKey(data);
            BigInteger secret1 = user1.getSharedKey(data);
            Console.WriteLine(secret1 == secret2);
            Console.WriteLine(secret1.ToString("X"));
        }
        private static string ByteArrToHex(Byte[] result)
        {
            return BitConverter.ToString(result).Replace("-", String.Empty);
        }
        private static string ByteArrToUnicode(Byte[] result)
        {
            return Encoding.Unicode.GetString(result);
        }
        private static string ByteArrToBase64(Byte[] result)
        {
            return Convert.ToBase64String(result);
        }

        private static byte[] HexToByteArr(string hex)
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

        private static byte[] UnicodeToByteArr(string unicode)
        {
            return Encoding.Unicode.GetBytes(unicode);
        }
        private static byte[] Base64ToByteArr(string base64)
        {
            return Convert.FromBase64String(base64);
        }
    }
}


