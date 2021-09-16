package com.cryptodotcom;

import org.junit.jupiter.api.Test;
import com.cryptodotcom.types.EnclaveQuoteStatus;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

class EnclaveCertVerifierTest {

    @Test
    void verifyAttestationReport() throws IOException, CertificateException, URISyntaxException {
        ClassLoader classLoader = this.getClass().getClassLoader();
        Path filePath = Paths.get(classLoader.getResource("valid_attestation_report.json").toURI());
        byte[] attestationReport = Files.readAllBytes(filePath);
        byte[] reportData = Base64.getDecoder().decode("1g+Nvsow2LXbrJVq/8YS5wMUd+GTeOkBegUmnGtcfyLSS0qP6ufwO2HEDV70O4W/tFDx57tziaOWd6OJjenAeg==");
        byte[] publicKey = new byte[reportData.length + 1];
        publicKey[0] = 4;
        System.arraycopy(reportData, 0, publicKey, 1, publicKey.length - 1);

        Set<EnclaveQuoteStatus> validStatuses = new HashSet<>();
        validStatuses.add(EnclaveQuoteStatus.OK);
        validStatuses.add(EnclaveQuoteStatus.CONFIGURATION_AND_SW_HARDENING_NEEDED);

        InputStream inputStream = classLoader.getResourceAsStream("AttestationReportSigningCACert.der");
        EnclaveCertVerifier verifier = new EnclaveCertVerifier(validStatuses, Duration.ofSeconds(86400), inputStream);

        Date now = Date.from(Instant.ofEpochSecond(1594612800));
        verifier.verifyAttestationReport(attestationReport, publicKey, now);
    }
}