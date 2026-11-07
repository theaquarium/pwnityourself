import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.OutputStream;
import java.net.InetSocketAddress;

/**
 * A deliberately vulnerable web service.
 * It logs the incoming User-Agent header with Log4j 2.14.1 -- the classic
 * Log4Shell (CVE-2021-44228) sink: untrusted input reaches the logger, and
 * Log4j performs JNDI lookups on ${jndi:...} substrings it finds there.
 */
public class VulnerableApp {
    private static final Logger logger = LogManager.getLogger(VulnerableApp.class);

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", new HttpHandler() {
            @Override
            public void handle(HttpExchange ex) throws java.io.IOException {
                String ua = ex.getRequestHeaders().getFirst("User-Agent");
                // VULNERABLE: user-controlled input flows straight into the logger.
                logger.error("Incoming request from User-Agent: {}", ua);
                String resp = "200 OK - your request was logged.\n";
                byte[] b = resp.getBytes();
                ex.sendResponseHeaders(200, b.length);
                OutputStream os = ex.getResponseBody();
                os.write(b);
                os.close();
            }
        });
        server.setExecutor(null);
        System.out.println("[victim] Vulnerable app listening on :" + port);
        server.start();
    }
}
