import org.postgresql.ds.PGSimpleDataSource;
import javax.sql.DataSource;
import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.net.ssl.*;

public class PostgreSQLSSLMemoryDataSource {

    // Database configuration
    private static final String DB_HOST = "your-db-host";
    private static final int DB_PORT = 5432;
    private static final String DB_NAME = "your-db-name";
    private static final String DB_USER = "your-db-user";

    // PEM-format strings
    private static final String CLIENT_CERT_PEM = """
        -----BEGIN CERTIFICATE-----
        YOUR_CLIENT_CERTIFICATE_HERE
        -----END CERTIFICATE-----""";
        
    private static final String CLIENT_KEY_PEM = """
        -----BEGIN PRIVATE KEY-----
        YOUR_PRIVATE_KEY_HERE
        -----END PRIVATE KEY-----""";
        
    private static final String CA_CERT_PEM = """
        -----BEGIN CERTIFICATE-----
        YOUR_CA_CERTIFICATE_HERE
        -----END CERTIFICATE-----""";

    static {
        try {
            // Parse certificates and private key
            X509Certificate clientCert = parsePemCertificate(CLIENT_CERT_PEM);
            X509Certificate caCert = parsePemCertificate(CA_CERT_PEM);
            PrivateKey privateKey = parsePemPrivateKey(CLIENT_KEY_PEM);

            // Create in-memory keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("client-key", 
                privateKey, 
                "".toCharArray(), 
                new Certificate[]{clientCert, caCert}
            );

            // Create in-memory truststore
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, null);
            trustStore.setCertificateEntry("ca-cert", caCert);

            // Initialize SSL context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
            );
            tmf.init(trustStore);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm()
            );
            kmf.init(keyStore, "".toCharArray());

            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            
            // Set as default SSL context
            SSLContext.setDefault(sslContext);
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize SSL context", e);
        }
    }

    public static DataSource getDataSource() {
        PGSimpleDataSource dataSource = new PGSimpleDataSource();
        dataSource.setServerNames(new String[]{DB_HOST});
        dataSource.setPortNumbers(new int[]{DB_PORT});
        dataSource.setDatabaseName(DB_NAME);
        dataSource.setUser(DB_USER);
        
        // Enable SSL with full verification
        dataSource.setSsl(true);
        dataSource.setSslMode("verify-full");
        
        return dataSource;
    }

    private static X509Certificate parsePemCertificate(String pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(
            new ByteArrayInputStream(pem.getBytes())
        );
    }

    private static PrivateKey parsePemPrivateKey(String pem) throws Exception {
        String privateKeyContent = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
            
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyContent);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }
}
