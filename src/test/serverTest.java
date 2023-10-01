import org.junit.Test;
import static org.junit.Assert.*;
import org.evosuite.runtime.EvoRunner;
import org.evosuite.runtime.EvoRunnerParameters;
import org.junit.runner.RunWith;

@RunWith(EvoRunner.class) @EvoRunnerParameters(mockJVMNonDeterminism = true, useVFS = true, useVNET = true, resetStaticState = true, separateClassLoader = true, useJEE = true)
public class serverTest {
    @Test // used for testing
    public void testGenerateRSAKeyPair() {
        JWKSServer server = new JWKSServer();
        assertNotNull(server.generateRSAKeyPair());
    }

    @Test
    public void testBuildJWKSResponse() {
        JWKSServer server = new JWKSServer();
        assertNotNull(server.buildJWKSResponse(server.generateRSAKeyPair()));
    }

    @Test
    public void testGenerateJWTWithExpiry() {
        JWKSServer server = new JWKSServer();
        String token = server.generateJWTWithExpiry(false); // Check for a valid token
        assertNotNull(token);
    }
}