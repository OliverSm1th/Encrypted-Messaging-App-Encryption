using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace Encrypted_Messaging_Program
{
    public class KeyData
    {
        public BigInteger prime { get; set; }
        public int global { get; set; }
        public BigInteger A_Key { get; set; }
        public BigInteger B_Key { get; set; }
        public KeyData() { }
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
}
