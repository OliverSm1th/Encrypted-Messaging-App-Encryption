using Firebase.Database;
using Firebase.Database.Query;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Linq;
using System.Reactive.Linq;


//{ p, g, A, B}
namespace Encrpytion_Prototype
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
            Console.WriteLine("\nInitilising DiffieHellman");

            Program test = new Program();
            //test.testDH();
            test.testAES();
            //test.testRequest().Wait();
            Console.WriteLine("Test finished.....");

            //new Program().SendRequest(userID, data).Wait();

        }

        private void testAES()
        {
            BigInteger sharedKey = BigInteger.Parse("0E4723DB0E789861C3E3436D6CD9191C2059A8FFFE08FC3DC5991DF72F41EE465FB55BB030AD0F736EBACA87C4272DB53973FE7ACD9AFDAF3666337D9B46400DC02F4838AE697505DC7CC1E433375FDCB5191144AA1769015540ABDBC9A507B5630C9DD0D503A94F1CD6105241754D08F0C8D7496E22CC618E42BCB9A1C5EB4C90157759C330B8B53C3F2B17488C985F35D70163822644F79F73F710483660BCF03FB923CB57352173E68BE0A03A29CA3639FEA014767389355BA73324544E227", System.Globalization.NumberStyles.AllowHexSpecifier);
            String message = "Hello, this is a test message :)";

            AES test = new AES(192, true);  // Using inbuilt function for now....
            test.Encrypt(sharedKey, message);
        }

        private async Task testRequest()
        {
            Console.Write("Enter your user ID:  ");
            string userID = Console.ReadLine();
            //new Program().GetRequests(userID).Wait();
            Request Requests = new Request(firebase, userID);


            bool stop = false;
            while (!stop)
            {
                Console.WriteLine("--Menu--\n1) Send Request\n2) Accept Request\n3) Change user\n");
                string choice = Console.ReadLine();
                bool success = Int32.TryParse(choice, out int int_choice);
                if (success && int_choice <= 3 && int_choice > 0)
                {
                    switch (int_choice)
                    {
                        case 1:
                            Console.Write("Enter user:  ");
                            string requestUser = Console.ReadLine();
                            DiffieHellman user1 = new DiffieHellman(256);

                            await SendRequest(userID, requestUser, user1.Initilise());
                            break;
                        case 2:
                            Console.WriteLine("Pending Requests:");


                            string[] requestID = await Requests.GetAll();
                            foreach (string request in requestID)
                            {
                                Console.WriteLine(request);
                            }


                            Console.WriteLine();
                            Console.WriteLine("Enter user to accept: ");
                            string acceptUser = Console.ReadLine();
                            if (acceptUser.Length > 0)
                            {
                                string Data = Requests.GetData(acceptUser).output();
                                Console.WriteLine($"Done: {Data}");
                            }
                            break;
                    }
                }
            }
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

        public async Task<string[]> GetRequests(string userID)
        {
            var items = firebase.Child("users").Child(userID).Child("requests").OnceAsync<KeyData>();

            var requestID = new List<string>();

            foreach (var pair in await items)
            {
                //Console.WriteLine($"{pair.Key} : {pair.Object}");
                requestID.Add(pair.Key);
            }
            return requestID.ToArray();
        }

        /*public async Task<BigInteger[]> GetRequest(string userID, string requestID)
        {
            var items = firebase.Child("users").Child(userID).Child("requests").Child("").OnceAsync<KeyData>();

            return items[requestID];
            //https://bolorundurowb.com/posts/31/using-the-firebase-realtime-database-with-.net
        }*/


        private async Task SendRequest(string userID, String requestID, KeyData data)
        {
            await firebase.Child("users").Child(requestID).Child("requests").Child(userID).PostAsync(data);
            Console.WriteLine("Done");
        }

    }

    class Request
    {
        Dictionary<string, KeyData> requests = new Dictionary<string, KeyData>();
        String userID;
        public FirebaseClient firebase;
        public Request(FirebaseClient p_firebase, string p_userID)
        {
            userID = p_userID;
            firebase = p_firebase;
            fillRequests(userID);


        }

        private async Task fillRequests(string userID){
            var child = firebase.Child("users").Child(userID).Child("requests");
            var observable = child.AsObservable<KeyData>();
            var items = await child.OnceAsync<KeyData>();
            requests.Clear();
            //Object[] types = items.GetType().GetMethods();
            //Console.WriteLine(String.Join("\n", types));
            //foreach (var item in items)
            //{
                //requests.Add(item.Key, item.Object);
                //Console.WriteLine($"{item.Key}: {item.Object}");
            //}
            var subscription = observable
                .Where(x => !string.IsNullOrEmpty(x.Key))
                .Where(x => !requests.ContainsKey(x.Key))
                .Subscribe(s => requests.Add(s.Key, s.Object));
        }

        public async Task<String[]> GetAll() //<List<KeyValuePair<string, KeyData>>>
        {
            if(requests.Count == 0){
                Console.WriteLine("Requests incomplete, fetching again");
                await fillRequests(userID);
            }
            return requests.Keys.ToArray();
        }

        public KeyData GetData(string requestID)
        {
            return requests[requestID];
        }

    }

}

//-r:System.Numerics.dll


