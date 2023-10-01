import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Main {
    private static final String AUTH_ENDPOINT = "/auth";
    private static final String JWKS_ENDPOINT = "/.JWKSServer/jwks.json";

    public static void main(String[] args) {
        Grammar grammar = new Grammar();
        grammar.run();
    }

    static class Grammar {
        private int port = 8080;
        private boolean debug = false;
        private boolean total = false;

        public void run() {
            // Set up logging.
            Slog.LevelVar lvl = new Slog.LevelVar();
            SlogHandler handler = new SlogHandler(System.err, lvl);
            Slog logger = new Slog(handler);
            if (debug) {
                lvl.set(Slog.LevelDebug);
            }
            if (total) {
                lvl.set(10);
            }
            Slog.setDefault(logger);

            Context rubric = new Context();
            rubric.setHostURL("http://127.0.0.1:" + port);

            Result[] results = new Result[5];

            results[0] = checkAuthentication(rubric);
            results[1] = checkProperHTTPMethodsAndStatusCodes(rubric);
            results[2] = checkValidJWKFoundInJWKS(rubric);
            results[3] = checkExpiredJWTIsExpired(rubric);
            results[4] = checkExpiredJWKNotFoundInJWKS(rubric);

            if (total) {
                int totalPoints = 0;
                for (Result result : results) {
                    totalPoints += result.getAwarded();
                }
                System.out.println(totalPoints);
            } else {
                // Print the results as a table.
                Table table = new Table();
                table.appendHeader("Rubric Item", "Error?", "Points Awarded");
                table.setStyle(Table.Style.ROUNDED);

                int possiblePoints = 0;
                int totalPoints = 0;
                for (Result result : results) {
                    table.appendRow(result.getLabel(), result.getMessage(), result.getAwarded());
                    possiblePoints += result.getPossible();
                    totalPoints += result.getAwarded();
                }
                table.appendFooter("", "Possible", possiblePoints);
                table.appendFooter("", "Awarded", totalPoints);
                System.out.println(table.render());
            }
        }

        // Implement other methods and classes here.
        // ...

        static class Context {
            private String hostURL;
            private JwtToken validJWT;
            private JwtToken expiredJWT;

            public void setHostURL(String hostURL) {
                this.hostURL = hostURL;
            }

            // Implement getters and setters for other properties as needed.
            // ...
        }

        // Implement other inner classes as needed.
        // ...
    }

    // Implement other classes and methods as needed.
    // ...
}

class Slog {
    public static final int LevelDebug = 0;

    static class LevelVar {
        private int level;

        public void set(int level) {
            this.level = level;
        }
    }

    static class HandlerOptions {
        private int level;

        public HandlerOptions(int level) {
            this.level = level;
        }
    }

    static class Handler {
        public Handler(HandlerOptions options) {
            // Initialize the handler with the specified options.
        }
    }

    public Slog(Handler handler) {
        // Initialize the logger with the specified handler.
    }

    public static void setDefault(Slog logger) {
        // Set the default logger to the specified logger.
    }

    public static Slog getDefault() {
        // Get the default logger.
        return null; // Replace with actual implementation.
    }

    public boolean isEnabled(Object context, int level) {
        // Check if logging at the specified level is enabled.
        return false; // Replace with actual implementation.
    }

    public void debug(String message, Object... args) {
        // Log a debug message.
    }

    public void error(String message, Object... args) {
        // Log an error message.
    }
}

class Table {
    public enum Style {
        ROUNDED
    }

    public void appendHeader(String... columns) {
        // Append a header row to the table.
    }

    public void appendRow(Object... cells) {
        // Append a data row to the table.
    }

    public void appendFooter(String... cells) {
        // Append a footer row to the table.
    }

    public void setStyle(Style style) {
        // Set the table style.
    }

    public String render() {
        // Render the table as a string.
        return ""; // Replace with actual implementation.
    }
}

class JwtToken {
    // Implement JwtToken class as needed.
    // ...
}

class Result {
    private String label;
    private int awarded;
    private int possible;
    private String message;

    public String getLabel() {
        return label;
    }

    public int getAwarded() {
        return awarded;
    }

    public int getPossible() {
        return possible;
    }

    public String getMessage() {
        return message;
    }
}