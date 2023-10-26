// Brandon Sharp, CSCS 3550
// Project 2: Extending the JWKS Server from the basic Restful JWKS Server
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.time.Instant;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
//import io.jsonwebtoken.security.Keys;

// Project 2 imports
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.math.BigInteger;
import java.security.PublicKey;

public class JWKSServer {
    public class MyStruct { // Creates a class that acts like a struct
        public String username; // Contains fields
        public String password;
        public String goodKID;

        public MyStruct(String username, String password, String goodKID) {
            this.username = username;
            this.password = password;
            this.goodKID = goodKID;
        }
    }

    private static final String SECRET_KEY = "your-secret-key"; // Change this to your own secret key

    public static void main(String[] args) throws IOException {
        // This function is the first step to creating and authenticating the server
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/.well-known/jwks.json", new JWKSHandler()); // Handles that website link
        server.createContext("/auth", new AuthHandler()); // Creates the authenticator
        server.setExecutor(null); // Creates a default executor
        server.start();
        System.out.println("Server is running on port 8080....."); // Testing
    }

    static class JWKSHandler implements HttpHandler {
        // This function handles http request GET
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, "Method Not Found", 405);
                return;
            }
            // sendResponse(exchange, "{\"keys\":[]}", 200);
            KeyPair keyPair = generateRSAKeyPair(); // Generates an RSA key pair
            if (keyPair != null) { // If not null then it continues
                String jwksResponse = buildJWKSResponse(keyPair); // Builds the JWKS JSON response
                StoreKeyPairInDatabase(keyPair); // P2: Stores the key pair in the database
                sendResponse(exchange, jwksResponse, 200); // Sends the JWKS response
            } else {
                sendResponse(exchange, "Key pair is null", 404); // Handles the null keyPair
            }
        }

        private KeyPair generateRSAKeyPair() {
            // Generates an RSA private key maybe (you get a public key for free)
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048); // The key size can be adjusted
                return keyPairGenerator.generateKeyPair();
            } catch (Exception e) {
                e.printStackTrace();
                //t.sendResponseHeaders(500, -1); // 500 is Internal Server Error
                return null;
            }
        }

        private String buildJWKSResponse(KeyPair keyPair) {
            // Formats the RSA public key required by JWKS
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            String modulus = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getModulus().toByteArray());
            String exponent = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getPublicExponent().toByteArray());
            return String.format("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"1\",\"n\":\"%s\",\"e\":\"%s\"}]}", modulus, exponent);
        }
    }

    // final String goodKID = "aRandomKeyID";

    static class AuthHandler implements HttpHandler {
        // This function handles the http request POST
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, "Method Not Found", 405);
                return;
            }
            String allowExpiredParam = exchange.getRequestHeaders().getFirst("Allow-Expired");
            boolean allowExpired = "true".equalsIgnoreCase(allowExpiredParam);
            String token = generateJWTWithExpiry(allowExpired);
            sendResponse(exchange, token, 200);
        }

        private String generateJWTWithExpiry(boolean allowExpired) {
            // This function encodes the JWT
            Instant now = Instant.now();
            // Token expires in 1 hour or is already expired
            Instant expirationTime = allowExpired ? now.minusSeconds(3600) : now.plusSeconds(3600);

            // P2: Retrieves the key pair from the database and checks if keyPair is null
            KeyPair keyPair = GetKeyPairFromDatabase();
            if (keyPair != null) {
                RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
                String secretKey = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getModulus().toByteArray());

                return Jwts.builder()
                        .setSubject("user123") // The subject/username will be set as needed
                        .setIssuedAt(java.util.Date.from(now))
                        .setExpiration(java.util.Date.from(expirationTime))
                        .signWith(SignatureAlgorithm.HS256, secretKey) // Using the public key as the secret key
                        .compact();
            }
            else {
                // If the key pair is not found in the database
                return "Key pair not found";
            }
        }
    }

    private static void sendResponse(HttpExchange exchange, String response, int statusCode) throws IOException {
        // This function prepares to send a response
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(statusCode, response.length());
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    private static void StoreKeyPairInDatabase(KeyPair keyPair) {
        // P2 function: This function stores the key pair into the database
        Connection conn = null;
        try {
            conn = DriverManager.getConnection("jdbc:sqlite:totally_not_my_privateKeys.db"); // Connects with the db file
            if (conn != null) {
                RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
                String modulus = Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(publicKey.getModulus().toByteArray());
                String exponent = Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(publicKey.getPublicExponent().toByteArray());

                String insertQuery = "INSERT INTO public_keys (modulus, exponent) VALUES (?, ?)";
                try (PreparedStatement pstmt = conn.prepareStatement(insertQuery)) {
                    pstmt.setString(1, modulus);
                    pstmt.setString(2, exponent);
                    pstmt.executeUpdate();
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
    private static KeyPair GetKeyPairFromDatabase() {
        // P2 function: This function gets the key pair from the database
        Connection conn = null;
        try {
            conn = DriverManager.getConnection("jdbc:sqlite:totally_not_my_privateKeys.db"); // Connects with the db file
            if (conn != null) {
                String selectQuery = "SELECT modulus, exponent FROM public_keys";
                try (Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery(selectQuery)) {
                    if (rs.next()) {
                        byte[] modulusBytes = Base64.getUrlDecoder().decode(rs.getString("modulus"));
                        byte[] exponentBytes = Base64.getUrlDecoder().decode(rs.getString("exponent"));

                        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(1, modulusBytes), new BigInteger(1, exponentBytes));

                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

                        // You need the corresponding private key to create a full KeyPair,
                        // but since this is just for verifying JWT, you only need the public key.
                        return new KeyPair(publicKey, null);
                    }
                } catch (NoSuchAlgorithmException e) { // This catch clause is here for getInstance()
                    throw new RuntimeException(e);
                }
            }
        } catch (SQLException | InvalidKeySpecException e) { // Catch clauses for these two things
            e.printStackTrace();
        } finally {
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        return null;
    }
}
