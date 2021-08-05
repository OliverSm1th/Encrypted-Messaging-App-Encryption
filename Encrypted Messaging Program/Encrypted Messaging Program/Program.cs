using Firebase.Database;
using Firebase.Database.Query;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Linq;
using System.Reactive.Linq;
using Google.Cloud.Firestore;


//{ p, g, A, B}
namespace Encryption_Prototype
{
    /*public class KeyData
    {
        public String Data { get; set; }
        public BigInteger prime { get; set; }
        public int g { get; set; }
        public BigInteger A { get; set; }
        public BigInteger B { get; set; }
        public KeyData(BigInteger prime_, int g_, BigInteger secret, int userNum)
        {
            prime = prime_;
            g = g_;
            if(userNum == 0){
                A = secret;
            }
            else{
                B = secret;
            }
        }
    }
    */


    public class Program
    {
        public FirebaseClient firebase = new FirebaseClient("https://messaging-app-demo-348e5-default-rtdb.europe-west1.firebasedatabase.app/");
        public static void Main(string[] args)
        {

            //Program test = new Program();

            // Diffie Hellman Test:
            //test.testDH();
            // AES Test:
            //test.testAES();
            //test.exampleAES();

            
            
            
            
            Console.WriteLine("Test finished.....");

            //test.testRequest().Wait();
            //new Program().SendRequest(userID, data).Wait();

        }

        private void testAES()
        {
            //BigInteger sharedKey = BigInteger.Parse("0E4723DB0E789861C3E3436D6CD9191C2059A8FFFE08FC3DC5991DF72F41EE465FB55BB030AD0F736EBACA87C4272DB53973FE7ACD9AFDAF3666337D9B46400DC02F4838AE697505DC7CC1E433375FDCB5191144AA1769015540ABDBC9A507B5630C9DD0D503A94F1CD6105241754D08F0C8D7496E22CC618E42BCB9A1C5EB4C90157759C330B8B53C3F2B17488C985F35D70163822644F79F73F710483660BCF03FB923CB57352173E68BE0A03A29CA3639FEA014767389355BA73324544E227", System.Globalization.NumberStyles.AllowHexSpecifier);
            String message = "Hello, this is a test message :)";

            AES test = new AES(128, true, "hex");  // Using inbuilt function for now....
            Byte[] result = test.Encrypt("2b7e151628aed2a6abf7158809cf4f3c", "theblockbreakers");
            Console.WriteLine(test.Decrypt("2b7e151628aed2a6abf7158809cf4f3c", result));
        }
        private void exampleAES()
        {
            BigInteger sharedKey = BigInteger.Parse("2b7e", System.Globalization.NumberStyles.AllowHexSpecifier);//2b7e151628aed2a6abf7158809cf4f3c
            String message = "Hello, this is an example message :)";
            Console.WriteLine($"Encrypt({sharedKey}, {message})");
            AES test = new AES(128, true, "hex");
            string result = test.Decrypt("2b7e151628aed2a6abf7158809cf4f3c", "3925841d02dc09fbdc118597196a0b32", true);
            //Byte[] result = test.Encrypt("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734", true);
            Console.WriteLine($"Final Result: \n{result}");
        }

        private string ByteToHex(byte[] input, string seperator = "")
        {
            return BitConverter.ToString(input).Replace("-", seperator);
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

    }

    class textMessagingApp
    {
        public textMessagingApp()
        {
            // Initilise server
            Firestore server = new Firestore("encrypted-messaging-app");
            server.GetUser("0000").Wait();
            server.SetNewUser("0000", "password").Wait();
            Console.WriteLine("--Messaging Program--\n1) Log in\n2) Register");
            string choice = getInput("--Messaging Program--\n1) Log in\n2) Register", "Invalid choice given", new string[] { "1", "2" }, maxLength:1);
            if (choice == "1")         // Log in
            {
                Console.WriteLine("--- Log-in ---");
                string username = getInput("Username: ", "Invalid username given", sameLine: true, maxLength:15, minLength:5);
                string password = getInput("Password: ", "Invalid password given", sameLine: true, maxLength:15, minLength:5);

            }
            else if (choice == "2") // Register
            {

            }
            else
            {

            }

        }

        public string getInput(string requestMsg, string errorMsg, string[] options = null, int maxLength = 100, int minLength = 0, bool sameLine = false)
        {
            bool valid = false;
            string value = "";
            while (!valid)
            {
                if (sameLine)
                {
                    Console.Write(requestMsg);
                }
                else
                {
                    Console.WriteLine(requestMsg);
                }
                
                
                value = Console.ReadLine();
                
                valid = true;
                if ((options.Length > 0 && !options.Contains(value)) || (options.Length > maxLength || options.Length < minLength))
                {
                    valid = false;
                    Console.WriteLine(errorMsg);
                }
            }
            return value;
        }
    }


}

//-r:System.Numerics.dll


