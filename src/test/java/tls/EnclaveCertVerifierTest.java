package tls;

import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtil;
import org.junit.jupiter.api.Test;
import tls.types.EnclaveQuoteStatus;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.*;

class EnclaveCertVerifierTest {

    @Test
    void verifyAttestationReport() throws IOException, NoSuchAlgorithmException, CertificateException, InvalidKeySpecException {
        ClassLoader classLoader = this.getClass().getClassLoader();
        Path filePath = Path.of(Objects.requireNonNull(classLoader.getResource("valid_attestation_report.json")).getPath());
        byte[] attestationReport = Files.readAllBytes(filePath);
        byte[] reportData = Base64.getDecoder().decode("1g+Nvsow2LXbrJVq/8YS5wMUd+GTeOkBegUmnGtcfyLSS0qP6ufwO2HEDV70O4W/tFDx57tziaOWd6OJjenAeg==");
        byte[] publicKey = new byte[reportData.length + 1];
        publicKey[0] = 4;
        System.arraycopy(reportData, 0, publicKey, 1, publicKey.length - 1);

        Set<EnclaveQuoteStatus> validStatuses = new HashSet<>();
        validStatuses.add(EnclaveQuoteStatus.OK);
        validStatuses.add(EnclaveQuoteStatus.CONFIGURATION_AND_SW_HARDENING_NEEDED);

        EnclaveCertVerifier verifier = new EnclaveCertVerifier(validStatuses, Duration.ofSeconds(86400));
        Date now = new Date();
        verifier.verifyAttestationReport(attestationReport, publicKey, now);
    }
}