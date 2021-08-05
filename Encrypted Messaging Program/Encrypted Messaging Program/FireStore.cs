using System;
using System.Collections.Generic;
using System.Text;
using Google.Cloud.Firestore;
using Google.Cloud.Firestore.V1;
using Google.Apis.Auth;
using Google.Apis.Services;
using System.Threading.Tasks;
using Firebase.Auth;

namespace Encryption_Prototype
{
    



    class Firestore
    {
        FirestoreDb db;

        public Dictionary<string, object> initialUser = new Dictionary<string, object>
        {
            {"password", "" },
            {"Chats", new Dictionary<string, object>{ } },
            {"Requests", new Dictionary<string, object> { } }
        };


        public Firestore(string databaseID)
        {
            
            Environment.SetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS", "D:/Documents/Computing/NEA A-Level Project/Encrypted-Messaging-App/encrypted-messaging-app-b689c5915859.json");
            db = FirestoreDb.Create(databaseID);
            Console.WriteLine($"Created Cloud Firestore client with project ID: {databaseID}");
            
        }

        async public Task<Dictionary<string, object>> GetUser(string id)
        {
            CollectionReference userRef = db.Collection("users");
            Console.WriteLine("Awaiting result");
            DocumentSnapshot document = await userRef.Document(id).GetSnapshotAsync();
            Console.WriteLine($"---User : {document.Id}---");
            Dictionary<string, object> documentDictionary = document.ToDictionary();

            foreach(KeyValuePair<string, object> entry in documentDictionary)
            {
                Console.WriteLine($"{entry.Key}: {entry.Value}");
            }
            return documentDictionary;
        }
        async public Task GetUsers()
        {
            CollectionReference usersRef = db.Collection("users");
            QuerySnapshot snapshot = await usersRef.GetSnapshotAsync();
            Console.WriteLine("---Users---");
            foreach (DocumentSnapshot document in snapshot.Documents)
            {
                Console.WriteLine("User: {0}", document.Id);
            }
        }
        


        async public Task SetNewUser(string id, string enc_password)
        {
            DocumentReference userRef = db.Collection("users").Document(id);
            Dictionary<string, object> user = initialUser;
            user["password"] = enc_password;
            await userRef.SetAsync(user);
            Console.WriteLine("Added it!!");
        }

        public string UserToId(string username)
        {
            return username;
        }
    }

    class FireAuth
    {
        FirebaseAuthProvider authProvider;
        public FireAuth()
        {
            authProvider = new FirebaseAuthProvider(new FirebaseConfig("AIzaSyA2PGIeoXc8RtlqS-oSKenxrO8RCcH64HA"));
        }

        public Task<bool> SignIn(string email, string password)
        {
            var userCredential = authProvider.SignInWithEmailAndPasswordAsync(email, password);

        }
        
        
    }
}
