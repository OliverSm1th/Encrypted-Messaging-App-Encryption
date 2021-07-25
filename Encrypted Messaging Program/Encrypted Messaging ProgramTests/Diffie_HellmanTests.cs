using Microsoft.VisualStudio.TestTools.UnitTesting;
using Encryption_Prototype;
using System;
using System.Numerics;
using System.Collections.Generic;
using System.Text;

namespace DiffieHellmanTest
{
    [TestClass]
    
    public class Diffie_HellmanTests
    {
        
        public KeyData data;
        public DiffieHellman DHTest_A;
        public DiffieHellman DHTest_B;



        [TestMethod]
        public void InitiliseTest()
        {
            KeyData value = new DiffieHellman().Initilise(14);
            Assert.IsNotNull(value.prime, "Prime not defined");
            Assert.IsNotNull(value.global, "Global not defined");
            Assert.IsNotNull(value.A_Key, "Secret key not defined");
            Assert.IsTrue((value.B_Key==0), $"Response key defined: {value.B_Key}");
            //Assert.IsTrue(Math.Floor(BigInteger.Log10(value.A_Key) + 1) == );
            //Assert.Fail();
        }

        [TestMethod]
        public void RespondTest()
        {
            DiffieHellman DHTest_A = new DiffieHellman();
            DiffieHellman DHTest_B = new DiffieHellman();

            KeyData data = DHTest_A.Initilise(14);
            data = DHTest_B.Respond(data);

            Assert.IsTrue((data.B_Key > 0), $"Response key not defined: {data.B_Key}");
        }

        //[TestInitialize]
        //public void getSharedKeyTestInit(){
            
            

            
        //}
        [TestMethod]
        public void getSharedKeyTest()
        {
            DiffieHellman DHTest_A = new DiffieHellman();
            DiffieHellman DHTest_B = new DiffieHellman();

            data = DHTest_A.Initilise(5, 5);
            data.A_Key = BigInteger.Parse("10B282EFA657A3072D05BC16BA73C704A9FB08C33BB82160FB84C65EA9B3C6E42DE1C8491B8F6BC90D09F6EC1EE3C07108F2D5D23E12127980CC4CD1DD8D8A1C50C2FC7C9EDCC36792FBCC556F20D8F5DD4EB41242B93D3263359779C7B4E0884B35A6190F6123E0E7DC55B7F1E0C75605ECF75B33232A489439AFC6A76B11A0052473D3DF9C3ADA405D701BA4074361BDDB366BFFCBD2A15F7209AEA91F4DDFC0D53AAB22A76B4FEDB931FBD1143A5DA481DDF993C9A2843E584950995F82A9", System.Globalization.NumberStyles.AllowHexSpecifier);
            data.B_Key = BigInteger.Parse("56F96E66145CF068F76D44B869D0AB7BA310100AE99E468684ED885249ECD45AF4638C8432D93417A24F714CD9040B04A95122ECBE29FC1D7341030F4A4853A8F173F2979A3652472D89D6989E06953037913664D85B9F14B85F44BD9A74F9230266534BE6DF4481DC2270E56457F5E7280BA30CC3C7A7AB6FB2C01E2B7205B3CAAE51F9B57D3C32B2741343FEB956B73A6EF15876BADF967900C6880DA624C4B722B7129D99D72CE70D735DBF0B68606330CD738FD808EC5CB3E5DD9D91096C", System.Globalization.NumberStyles.AllowHexSpecifier);
            DHTest_A.setPrivateKey(2317041632);

            BigInteger expectedValue = BigInteger.Parse("0E4723DB0E789861C3E3436D6CD9191C2059A8FFFE08FC3DC5991DF72F41EE465FB55BB030AD0F736EBACA87C4272DB53973FE7ACD9AFDAF3666337D9B46400DC02F4838AE697505DC7CC1E433375FDCB5191144AA1769015540ABDBC9A507B5630C9DD0D503A94F1CD6105241754D08F0C8D7496E22CC618E42BCB9A1C5EB4C90157759C330B8B53C3F2B17488C985F35D70163822644F79F73F710483660BCF03FB923CB57352173E68BE0A03A29CA3639FEA014767389355BA73324544E227", System.Globalization.NumberStyles.AllowHexSpecifier);
            BigInteger sharedKey = DHTest_A.getSharedKey(data);

            Assert.IsNotNull(sharedKey, "Shared key not returned");
            Assert.IsTrue(sharedKey == expectedValue, $"Invalid shared key calculated: {sharedKey}  {data.output()}"); //If all values shown are correct, the secret key is wrong
        }
    }
}