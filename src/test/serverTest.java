import org.junit.Test;
import static org.junit.Assert.*;
import org.evosuite.runtime.EvoRunner;
import org.evosuite.runtime.EvoRunnerParameters;
import org.junit.runner.RunWith;

@RunWith(EvoRunner.class) @EvoRunnerParameters(mockJVMNonDeterminism = true, useVFS = true, useVNET = true, resetStaticState = true, separateClassLoader = true, useJEE = true)
public class serverTest { //This will test the JWKSServer.java file by calling the functions to produce code coverage
    //@Test // used for testing
    //public void MyStruct() { //Will test
    //    JWKSServer server = new JWKSServer();
    //    assertNotNull(server.MyStruct()); //Checks if the RSA key pair was generated
    //}
    /*@Test // used for testing
    public void testGenerateRSAKeyPair() { //Will test the struct class
        JWKSServer server = new JWKSServer();
        assertNotNull(server.generateRSAKeyPair()); //Checks if the RSA key pair was generated
    }

    @Test
    public void testBuildJWKSResponse() { //Will test
        JWKSServer server = new JWKSServer();
        assertNotNull(server.buildJWKSResponse(server.generateRSAKeyPair())); //Checks for a JWKS response
    }
*/
    @Test
    public void testStoreKeyPairInDatabase() { //Will Test
        JWKSServer server = new JWKSServer();
        String token = server.StoreKeyPairInDatabase(RsaJsonWebKey keyPair); // Checks for storing the query
        assertNotNull(token);
    }
    @Test
    public void testGetKeyPairInDatabase() { //Will Test
        JWKSServer server = new JWKSServer();
        String token = server.GetKeyPairInDatabase(); // Checks for getting the query
        assertNotNull(token);
    }
}