//Brandon Sharp, CSCS 3550
//Project 1: Creating a basic Restful JWKS Server
import org.junit.Test;
import static org.junit.Assert.*;
//import static org.evosuite.runtime.EvoAssertions.*;
//import org.evosuite.runtime.EvoRunner;
//import org.evosuite.runtime.EvoRunnerParameters;
import org.junit.runner.RunWith;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
//import java.security.PrivateKey;
//import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.time.Instant;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
//import io.jsonwebtoken.security.Keys;

public class JWKSServer {
    public class MyStruct { //Creates a class that acts like a struct
        public String username; //Contains fields
        public String password;
        public MyStruct(String username, String password) {
            this.username = username;
            this.password = password;
        }
    }
    private static final String SECRET_KEY = "your-secret-key"; //Change this to your own secret key
    //@Test
    public static void main(String[] args) throws IOException {
        //This function is the first step to creating and authenticating the server
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/.JWKSServer/jwks.json", new JWKSHandler()); //Handles that website link
        server.createContext("/auth", new AuthHandler()); //Creates the authenticator
        server.setExecutor(null); //Creates a default executor
        server.start();
        System.out.println("Server is running on port 8080....."); //Testing
    }

    static class JWKSHandler implements HttpHandler {
        //This function handles http request GET
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, "Method Not Found", 405);
                return;
            }
            //sendResponse(exchange, "{\"keys\":[]}", 200);
            KeyPair keyPair = generateRSAKeyPair(); //Generates an RSA key pair
            if (keyPair != null) { //If not null then it continues
                String jwksResponse = buildJWKSResponse(keyPair); //Builds the JWKS JSON response
                sendResponse(exchange, jwksResponse, 200); //Sends the JWKS response
            }
            else {
                sendResponse(exchange, "Key pair is null", 404); //Handles the null keyPair
            }
        }

        private KeyPair generateRSAKeyPair() {
            //Generates an RSA private key maybe (you get a public key for free)
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048); // You can adjust the key size as needed
                return keyPairGenerator.generateKeyPair();
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
            //Get the public and private keys from the key pair
//          PublicKey publicKey = keyPair.getPublic();
//          PrivateKey privateKey = keyPair.getPrivate();
        }

        private String buildJWKSResponse(KeyPair keyPair) {
            //Formats the RSA public key required by JWKS
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            String modulus = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getModulus().toByteArray());
            String exponent = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getPublicExponent().toByteArray());

            return String.format("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"1\",\"n\":\"%s\",\"e\":\"%s\"}]}", modulus, exponent);
        }
    }

    //final String goodKID = "aRandomKeyID";

    static class AuthHandler implements HttpHandler {
        //This function handles the http request POST
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, "Method Not Found", 405);
                return;
            }
            // Generate a JWT token with an expiration time
//            String token = generateJWTWithExpiry();
//            sendResponse(exchange, token, 200);
//            sendResponse(exchange, "Authentication endpoint", 200);
            String allowExpiredParam = exchange.getRequestHeaders().getFirst("Allow-Expired");
            boolean allowExpired = "true".equalsIgnoreCase(allowExpiredParam);
            String token = generateJWTWithExpiry(allowExpired);
            sendResponse(exchange, token, 200);
        }

        private String generateJWTWithExpiry(boolean allowExpired) {
            //This function encodes the JWT
            Instant now = Instant.now();
            Instant expirationTime = allowExpired ? now.minusSeconds(3600) : now.plusSeconds(3600); // Token expires in 1 hour or is already expired
            //Instant expirationTime = now.plusSeconds(3600); // Token expires in 1 hour

            return Jwts.builder()
                .setSubject("user123") //Set subject/username as needed
                .setIssuedAt(java.util.Date.from(now))
                .setExpiration(java.util.Date.from(expirationTime))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY) //Change to preferred algorithm and key
                .compact();
        }
    }

    private static void sendResponse(HttpExchange exchange, String response, int statusCode) throws IOException {
        //This function prepares to send a response
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(statusCode, response.length());
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }
}

//Encodes your JWT
//JSON Data
/*let text = '{ "employees" : [' +
            '{ "firstName":"John" , "lastName":"Doe" },' +
            '{ "firstName":"Anna" , "lastName":"Smith" },' +
            '{ "firstName":"Peter" , "lastName":"Jones" } ]}';
            const obj = JSON.parse(text);
 */