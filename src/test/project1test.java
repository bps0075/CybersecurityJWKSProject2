import org.junit.Test;
import static org.junit.Assert.*;

public class JWKSServerTest {
    @Test
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
        // You can add more test cases for this method, like checking if the token is properly encoded.
    }
    // Add more test methods for other functionalities in your JWKSServer class.
}
