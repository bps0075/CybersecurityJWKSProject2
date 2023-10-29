// Brandon Sharp, CSCS 3550
// Project 2: Extending the JWKS Server from the basic Restful JWKS Server
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.time.Instant;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

// Project 2 (P2) imports
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
    //private static final String SECRET_KEY = "your-secret-key"; // Change this to your own secret key
    private static RsaJsonWebKey jwk = null;
    private static RsaJsonWebKey expiredJWK = null;
    private static Connection databaseConnection; // Private variable for the P2 database

    public static void main(String[] args) throws Exception {
        // Generates an RSA key pair, which will be used for signing and verification of the JWT and wrapped in a JWK
        jwk = RsaJwkGenerator.generateJwk(2048);
        jwk.setKeyId("goodKey1");
        expiredJWK = RsaJwkGenerator.generateJwk(2048);
        expiredJWK.setKeyId("expiredKey");

        initializeDatabaseConnection(); // Initializes the database connection for Project 2

        // This function is the first step to creating and authenticating the server
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/.well-known/jwks.json", new JWKSHandler()); // Handles that website link
        server.createContext("/auth", new AuthHandler()); // Creates the authenticator
        server.setExecutor(null); // Creates a default executor
        server.start();
        System.out.println("Server is running on port 8080....."); // Testing
    }

    private static void initializeDatabaseConnection() {
        String dbUrl = "jdbc:sqlite:totally_not_my_privateKeys.db";
        //String jdbcUrl = "jdbc:sqlite:totally_not_my_privateKeys.db";
        //String jdbcUrl = "jdbc:mysql://localhost:8080/totally_not_my_privateKeys.db";
        //String jdbcUrl = "jdbc:mysql://localhost:3306/totally_not_my_privateKeys.db";
        //String dbUsername = "test_username";
        //String dbPassword = "test_password";

        /*try {
            databaseConnection = DriverManager.getConnection(jdbcUrl, dbUsername, dbPassword);
            System.out.println("Database connection created.");
        } catch (SQLException e) {
            e.printStackTrace();
            System.err.println("Failed to connect to the database.");
        }*/

        try {
            Class.forName("org.sqlite.JDBC");
            databaseConnection = DriverManager.getConnection(dbUrl);
            System.out.println("Database connection established.");
        } catch (ClassNotFoundException | SQLException e) {
            e.printStackTrace();
            System.err.println("Failed to connect to the database.");
        }
    }

    static class JWKSHandler implements HttpHandler {
        // This function below handles http request GET and storing the key pair
        @Override
        public void handle(HttpExchange h) throws IOException {
            if (!"GET".equalsIgnoreCase(h.getRequestMethod())) {
                h.sendResponseHeaders(405, -1); // 405 means Method Not Allowed
                return;
            }

            // P2: Generates a new key pair
            //RsaJsonWebKey newKeyPair = RsaJwkGenerator.generateJwk(2048);
            //newKeyPair.setKeyId("newKey1");
            // P2: Stores the new key pair in the database
            storeKeyPairInDatabase(jwk);
            // P2: Generates a JSON Web Key Set (JWKS) response
            //JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(newKeyPair);
            //String jwks = jsonWebKeySet.toJson();

            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(jwk); // Generates a Json web key set
            String jwks = jsonWebKeySet.toJson();
            h.getResponseHeaders().add("Content-Type", "application/json");
            h.sendResponseHeaders(200, jwks.length());
            OutputStream os = h.getResponseBody();
            os.write(jwks.getBytes());
            os.close();
        }
    }

    static class AuthHandler implements HttpHandler {
        // This function below handles the http request POST and getting the key pair
        @Override
        public void handle(HttpExchange h) throws IOException {
            if (!"POST".equalsIgnoreCase(h.getRequestMethod())) {
                h.sendResponseHeaders(405, -1); // 405 means Method Not Allowed
                return;
            }
            // P2: Gets the key pair from the database
            String keyId = "newKey1"; // Replace with the appropriate key ID
            //RsaJsonWebKey keyPair = getKeyPairFromDatabase(keyId);
            PublicJsonWebKey keyPair = getKeyPairFromDatabase(keyId);

            /*if (keyPair != null) {
                // Use the retrieved key pair for JWT signing or verification
                // Signing a JWT
                /*JsonWebSignature jws = new JsonWebSignature();
                jws.setKeyIdHeaderValue(keyPair.getKeyId());
                jws.setKey(keyPair.getPrivateKey());*/

                // Creates the claims JWT claims and signs the token
            /*    JwtClaims claims = new JwtClaims();
                claims.setGeneratedJwtId(); // Sets it up with an id
                claims.setIssuedAtToNow(); // Gets issued
                claims.setSubject("sampleUser"); // Sets the user
                claims.setExpirationTimeMinutesInTheFuture(10); // Sets up JWT with expiry

                // Sends the JWT as a response
                JsonWebSignature jws = new JsonWebSignature();
                jws.setKeyIdHeaderValue(jwk.getKeyId());
                jws.setKey(jwk.getPrivateKey());

                // Checks for the expired query parameter
                if (h.getRequestURI().getQuery() != null && h.getRequestURI().getQuery().contains("expired=true")) {
                    NumericDate expirationTime = NumericDate.now();
                    expirationTime.addSeconds(-10 * 60); // Subtracts 10 minutes
                    claims.setExpirationTime(expirationTime);
                    jws.setKeyIdHeaderValue(expiredJWK.getKeyId());
                    jws.setKey(expiredJWK.getPrivateKey());
                }

                jws.setPayload(claims.toJson());
                jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

                String jwt = ""; // Start with a blank string
                try {
                    jwt = jws.getCompactSerialization(); // Tries to get it
                } catch (JoseException e) {
                    e.printStackTrace();
                    h.sendResponseHeaders(500, -1); // 500 means Internal Server Error
                    return;
                }

                h.sendResponseHeaders(200, jwt.length()); // 200 means OK
                OutputStream os = h.getResponseBody();
                os.write(jwt.getBytes());
                os.close();

            } else {
                // Handles the case when the key pair is not found in the database
                h.sendResponseHeaders(404, -1); // 404 means Not Found
                OutputStream os = h.getResponseBody();
                os.write("Key pair not found".getBytes());
                os.close();
            }*/

            // Creates the claims JWT claims and signs the token
            JwtClaims claims = new JwtClaims();
            claims.setGeneratedJwtId(); // Sets it up with an id
            claims.setIssuedAtToNow(); // Gets issued
            claims.setSubject("sampleUser"); // Sets the user
            claims.setExpirationTimeMinutesInTheFuture(10); // Sets up JWT with expiry

            JsonWebSignature jws = new JsonWebSignature();
            jws.setKeyIdHeaderValue(jwk.getKeyId());
            jws.setKey(jwk.getPrivateKey());

            // Checks for the expired query parameter
            if (h.getRequestURI().getQuery() != null && h.getRequestURI().getQuery().contains("expired=true")) {
                NumericDate expirationTime = NumericDate.now();
                expirationTime.addSeconds(-10 * 60); // Subtracts 10 minutes
                claims.setExpirationTime(expirationTime);
                jws.setKeyIdHeaderValue(expiredJWK.getKeyId());
                jws.setKey(expiredJWK.getPrivateKey());
            }

            jws.setPayload(claims.toJson());
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

            String jwt = ""; // Start with a blank string
            try {
                jwt = jws.getCompactSerialization(); // Tries to get it
            } catch (JoseException e) {
                e.printStackTrace();
                h.sendResponseHeaders(500, -1); // 500 means Internal Server Error
                return;
            }

            h.sendResponseHeaders(200, jwt.length()); // 200 means OK
            OutputStream os = h.getResponseBody();
            os.write(jwt.getBytes());
            os.close();
        }
    }

    private static void storeKeyPairInDatabase(RsaJsonWebKey keyPair) {
        // P2 function: This function stores the key pair into the SQLite database
        if (databaseConnection != null) {
            try {
                String insertQuery = "INSERT INTO jwks (kid, rsa_key) VALUES (?, ?)";
                PreparedStatement preparedStatement = databaseConnection.prepareStatement(insertQuery);
                preparedStatement.setString(1, keyPair.getKeyId());
                preparedStatement.setString(2, keyPair.toJson());

                preparedStatement.executeUpdate();
                preparedStatement.close();
                System.out.println("Key pair stored in the database.");
            } catch (SQLException e) {
                e.printStackTrace();
                System.err.println("Failed to store the key pair in the database.");
            }
        }
    }

    /*private static RsaJsonWebKey getKeyPairFromDatabase(String keyId) {
        // P2 function: This function gets the key pair from the SQLite database
        if (databaseConnection != null) {
            try {
                String selectQuery = "SELECT rsa_key FROM jwks WHERE kid = ?";
                PreparedStatement preparedStatement = databaseConnection.prepareStatement(selectQuery);
                preparedStatement.setString(1, keyId);

                ResultSet resultSet = preparedStatement.executeQuery();

                if (resultSet.next()) {
                    String keyJson = resultSet.getString("rsa_key");
                    return RsaJsonWebKey.Factory.newPublicJwk(keyJson);
                }

                preparedStatement.close();
            } catch (SQLException | JoseException e) {
                e.printStackTrace();
                System.err.println("Failed to retrieve the key pair from the database.");
            }
        }
        return null;
    }*/

    private static PublicJsonWebKey getKeyPairFromDatabase(String keyId) {
        if (databaseConnection != null) {
            try {
                String selectQuery = "SELECT rsa_key FROM jwks WHERE kid = ?";
                PreparedStatement preparedStatement = databaseConnection.prepareStatement(selectQuery);
                preparedStatement.setString(1, keyId);

                ResultSet resultSet = preparedStatement.executeQuery();

                if (resultSet.next()) {
                    String keyJson = resultSet.getString("rsa_key");
                    return PublicJsonWebKey.Factory.newPublicJwk(keyJson);
                }
                preparedStatement.close();
            } catch (SQLException | JoseException e) {
                e.printStackTrace();
                System.err.println("Failed to retrieve the key pair from the database.");
            }
        }
        return null;
    }
}

    /*private static void StoreKeyPairInDatabase(KeyPair keyPair) {
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

                String insertQuery = "INSERT INTO keys (modulus, exponent) VALUES (?, ?)";
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
                String selectQuery = "SELECT modulus, exponent FROM keys";
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

/*import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.time.Instant;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

public class JWKSServer {
    public static void main(String[] args) throws IOException {
        // This function is the first step to creating and authenticating the server
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/.well-known/jwks.json", new JWKSHandler()); // Handles the JWKS endpoint
        server.createContext("/auth", new AuthHandler()); // Creates the authenticator
        server.setExecutor(null); // Creates a default executor
        server.start();
        System.out.println("Server is running on port 8080....."); // Testing
    }

    static class JWKSHandler implements HttpHandler {
        // This function handles HTTP GET requests for JWKS
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, "Method Not Allowed", 405);
                return;
            }
            KeyPair keyPair = generateRSAKeyPair(); // Generates an RSA key pair
            if (keyPair != null) {
                String jwksResponse = buildJWKSResponse(keyPair); // Builds the JWKS JSON response
                sendResponse(exchange, jwksResponse, 200); // Sends the JWKS response
            } else {
                sendResponse(exchange, "Key pair is null", 404); // Handles the null keyPair
            }
        }

        private KeyPair generateRSAKeyPair() {
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                return keyPairGenerator.generateKeyPair();
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }

        private String buildJWKSResponse(KeyPair keyPair) {
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            String modulus = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getModulus().toByteArray());
            String exponent = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getPublicExponent().toByteArray());
            return String.format("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"1\",\"n\":\"%s\",\"e\":\"%s\"}]}", modulus, exponent);
        }
    }
    private static class AuthHandler implements HttpHandler {
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

        /*private String generateJWTWithExpiry(boolean allowExpired) {
            Instant now = Instant.now();
            Instant expirationTime = allowExpired ? now.minusSeconds(3600) : now.plusSeconds(3600);
            KeyPair keyPair = GetKeyPairFromDatabase();

            if (keyPair != null) {
                RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
                RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

                String token = Jwts.builder()
                        .setSubject("user123") // The subject/username will be set as needed
                        .setIssuedAt(java.util.Date.from(now))
                        .setExpiration(java.util.Date.from(expirationTime))
                        .signWith(SignatureAlgorithm.RS256, privateKey) // Using RS256 for RSA keys
                        .compact();

                return token;
            } else {
                return "Key pair not found";
            }
        }*/
/*        private String generateJWTWithExpiry(boolean allowExpired) {
            Instant now = Instant.now();
            Instant expirationTime = allowExpired ? now.minusSeconds(3600) : now.plusSeconds(3600);

            KeyPair keyPair = GetKeyPairFromDatabase();
            if (keyPair != null) {
                RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
                RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

                String token = Jwts.builder()
                        .setSubject("user123")
                        .setIssuedAt(Date.from(now))
                        .setExpiration(Date.from(expirationTime))
                        .signWith(SignatureAlgorithm.RS256, privateKey) // Using RS256 for RSA keys
                        .compact();

                return token;
            } else {
                return "Key pair not found";
            }
        }

    }

    private static void sendResponse(HttpExchange exchange, String response, int statusCode) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(statusCode, response.length());
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    private static KeyPair GetKeyPairFromDatabase() {
        Connection conn = null;
        try {
            conn = DriverManager.getConnection("jdbc:sqlite:totally_not_my_privateKeys.db");
            if (conn != null) {
                String selectQuery = "SELECT modulus, exponent FROM keys";
                try (Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery(selectQuery)) {
                    if (rs.next()) {
                        byte[] modulusBytes = Base64.getUrlDecoder().decode(rs.getString("modulus"));
                        byte[] exponentBytes = Base64.getUrlDecoder().decode(rs.getString("exponent"));

                        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(1, modulusBytes), new BigInteger(1, exponentBytes));

                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

                        return new KeyPair(publicKey, null);
                    }
                }
            }
        } catch (SQLException | InvalidKeySpecException | NoSuchAlgorithmException e) {
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
}*/
