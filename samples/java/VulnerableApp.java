/**
 * INTENTIONALLY VULNERABLE Java Servlet application.
 * FOR TESTING PURPOSES ONLY — DO NOT DEPLOY.
 */

import javax.servlet.http.*;
import java.io.*;
import java.security.*;
import java.sql.*;

public class VulnerableApp extends HttpServlet {

    // A02: Hardcoded credentials
    private static final String DB_PASSWORD = "admin123";
    private static final String SECRET_KEY = "hardcodedsecret";

    // ── A03: SQL Injection ────────────────────────────────────────────────────
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String userId = request.getParameter("id");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "root", DB_PASSWORD);
            // VULNERABLE: string concatenation in SQL
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
            PrintWriter out = response.getWriter();
            while (rs.next()) out.println(rs.getString(1));
        } catch (SQLException e) {
            // A09: Exception swallowed silently
        }
    }

    // ── A02: Weak hashing ─────────────────────────────────────────────────────
    public String hashPassword(String password) throws NoSuchAlgorithmException {
        // VULNERABLE: MD5 is broken
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return new String(hash);
    }

    // ── A03: Command Injection ────────────────────────────────────────────────
    public String ping(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        // VULNERABLE: user input in Runtime.exec
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        return new String(p.getInputStream().readAllBytes());
    }

    // ── A02: Insecure TLS ─────────────────────────────────────────────────────
    // VULNERABLE: trust-all certificate manager
    private static final javax.net.ssl.TrustManager[] trustAllCerts = {
        new javax.net.ssl.X509TrustManager() {
            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
        }
    };

    // ── A01: Path Traversal ───────────────────────────────────────────────────
    public String readFile(HttpServletRequest request) throws IOException {
        String filename = request.getParameter("file");
        // VULNERABLE: no path sanitisation
        File file = new File("/uploads/" + filename);
        return new String(new FileInputStream(file).readAllBytes());
    }
}
