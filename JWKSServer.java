//Brandon Sharp, CSCS 3550
//Project 1: Creating a basic Restful JWKS Server

/*import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class JWKSServer {
    //Static Variables
    private static final String HOSTNAME = "localhost"; // The hostname
    private static final int PORT = 8080; // The port number
    private static final int BACKLOG = 1;  // the backlog

    private static final String ALLOW_HEADER = "Allow";
    private static final String HEADER_CONTENT_TYPE = "Content-Type";

    private static final Charset CHARSET = StandardCharsets.UTF_8;

    private static final int STATUS_OK = 200;
    private static final int STATUS_METHOD_NOT_ALLOWED = 405;

    private static final int NO_RESPONSE_LENGTH = -1;

    private static final String METHOD_GET = "GET";
    private static final String METHOD_OPTIONS = "OPTIONS";
    private static final String ALLOWED_METHODS = METHOD_GET + "," + METHOD_OPTIONS;

    public static void main(final String... args) throws IOException {
        final HttpServer server = HttpServer.create(new InetSocketAddress(HOSTNAME, PORT), BACKLOG);
        server.createContext("/func1", he -> {
            try {
                final Headers headers = he.getResponseHeaders();
                final String requestMethod = he.getRequestMethod().toUpperCase();
                switch (requestMethod) {
                    case METHOD_GET:
                        final Map<String, List<String>> requestParameters = getRequestParameters(he.getRequestURI()); //requests the URI
                        // do something with the request parameters
                        final String responseBody = "['hello world!']";
                        headers.set(HEADER_CONTENT_TYPE, String.format("application/json; charset=%s", CHARSET));
                        final byte[] rawResponseBody = responseBody.getBytes(CHARSET);
                        he.sendResponseHeaders(STATUS_OK, rawResponseBody.length);
                        he.getResponseBody().write(rawResponseBody);
                        break;
                    case METHOD_OPTIONS:
                        headers.set(ALLOW_HEADER, ALLOWED_METHODS);
                        he.sendResponseHeaders(STATUS_OK, NO_RESPONSE_LENGTH);
                        break;
                    default:
                        headers.set(ALLOW_HEADER, ALLOWED_METHODS);
                        he.sendResponseHeaders(STATUS_METHOD_NOT_ALLOWED, NO_RESPONSE_LENGTH);
                        break;
                }
            } finally {
                he.close();
            }
        });
        server.start();
    }

    private static Map<String, List<String>> getRequestParameters(final URI requestUri) {
        final Map<String, List<String>> requestParameters = new LinkedHashMap<>();
        final String requestQuery = requestUri.getRawQuery();
        if (requestQuery != null) {
            final String[] rawRequestParameters = requestQuery.split("[&;]", -1);
            for (final String rawRequestParameter : rawRequestParameters) {
                final String[] requestParameter = rawRequestParameter.split("=", 2);
                final String requestParameterName = decodeUrlComponent(requestParameter[0]);
                requestParameters.putIfAbsent(requestParameterName, new ArrayList<>());
                final String requestParameterValue = requestParameter.length > 1 ? decodeUrlComponent(requestParameter[1]) : null;
                requestParameters.get(requestParameterName).add(requestParameterValue);
            }
        }
        return requestParameters;
    }

    private static String decodeUrlComponent(final String urlComponent) {
        try {
            return URLDecoder.decode(urlComponent, CHARSET.name());
        } catch (final UnsupportedEncodingException ex) {
            throw new InternalError(ex);
        }
    }
}*/

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
//import java.time.Instant;

//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
//import io.jsonwebtoken.security.Keys;

public class JWKSServer {
    //private static final String SECRET_KEY = "your-secret-key"; //Change this to your own secret key
    public static void main(String[] args) throws IOException {
        //This function is the first step to creating and authenticating the server
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/.well-known/jwks.json", new JWKSHandler()); //Handles that website link
        server.createContext("/auth", new AuthHandler()); //Creates the authenticator
        server.setExecutor(null); //Creates a default executor
        server.start();
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
            String jwksResponse = buildJWKSResponse(keyPair); //Builds the JWKS JSON response
            sendResponse(exchange, jwksResponse, 200); //Sends the JWKS response
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
//            // Get the public and private keys from the key pair
//            PublicKey publicKey = keyPair.getPublic();
//            PrivateKey privateKey = keyPair.getPrivate();
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
            sendResponse(exchange, "Authentication endpoint", 200);
        }

//        private String generateJWTWithExpiry() {
//            Instant now = Instant.now();
//            Instant expirationTime = now.plusSeconds(3600); // Token expires in 1 hour
//
//            return Jwts.builder()
//                    .setSubject("user123") // Set subject/username as needed
//                    .setIssuedAt(java.util.Date.from(now))
//                    .setExpiration(java.util.Date.from(expirationTime))
//                    .signWith(SignatureAlgorithm.HS256, SECRET_KEY) // Change to your preferred algorithm and key
//                    .compact();
//        }
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

/*let text = '{ "employees" : [' +
            '{ "firstName":"John" , "lastName":"Doe" },' +
            '{ "firstName":"Anna" , "lastName":"Smith" },' +
            '{ "firstName":"Peter" , "lastName":"Jones" } ]}';
            const obj = JSON.parse(text);
 */