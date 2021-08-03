import types.AttestationReport;
import types.AttestationReportBody;
import types.EnclaveQuoteStatus;
import types.Quote;

import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAccessor;
import java.util.*;
import java.util.stream.Collectors;

public class EnclaveCertVerifier implements X509TrustManager {
    private HashSet<EnclaveQuoteStatus> validEnclaveQuoteStatuses;
    private TrustAnchor rootCert;
    private Duration reportValidityDuration;

    private static final String OID_EXTENSION_ATTESTATION_REPORT = "2.16.840.1.113730.1.13";

    /**
     * @param validQuotes            Valid enclave quote statuses
     * @param reportValidityDuration Validity duration for enclave attestation report
     */
    public EnclaveCertVerifier(HashSet<EnclaveQuoteStatus> validQuotes, Duration reportValidityDuration) {
        ClassLoader classLoader = this.getClass().getClassLoader();
        File file = new File(Objects.requireNonNull(classLoader.getResource("AttestationReportSigningCACert.pem")).getFile());
        try (InputStream in = new FileInputStream(file)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate rootCert = (X509Certificate) certificateFactory.generateCertificate(in);
            this.rootCert = new TrustAnchor(rootCert, new byte[]{});
            this.validEnclaveQuoteStatuses = validQuotes;
            this.reportValidityDuration = reportValidityDuration;
        } catch (IOException | CertificateException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        throw new CertificateException("unimplemented");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        Date now = new Date();
        for (X509Certificate cert : x509Certificates) {
            cert.checkValidity(now);
            PublicKey publicKey = cert.getPublicKey();
            byte[] report = cert.getExtensionValue(OID_EXTENSION_ATTESTATION_REPORT);

            // Verify attestation report
            verifyAttestationReport(report, publicKey, now);

        }
    }

    private Quote verifyAttestationReport(byte[] reportBytes, PublicKey publicKey, Date now) throws CertificateException {
        AttestationReport attestationReport = AttestationReport.fromBytes(reportBytes);
        // read in certificate chain from PEM format
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(attestationReport.signing_cert);
        Collection<? extends Certificate> certs = certFactory.generateCertificates(in);
        X509Certificate endEntityCert = (X509Certificate) certs.stream().findFirst().orElseThrow(() -> new CertificateException("Could not get end-entity cert"));
        List<X509Certificate> x509Certificates = certs.stream().map((c) -> (X509Certificate) c).collect(Collectors.toList());

        try {
            verifyCertificates(x509Certificates, now);
        } catch (GeneralSecurityException e) {
            throw new CertificateException("Couldn't verify certificates", e);
        }

        PublicKey endEntityPublicKey = endEntityCert.getPublicKey();
        boolean isValid = verifyReportSignature(endEntityPublicKey, attestationReport.body, attestationReport.signature);
        if(!isValid) {
            throw new CertificateException("Attestation report signature invalid");
        }

        return verifyAttestationReportBody(attestationReport.body, publicKey, now);
    }

    private Quote verifyAttestationReportBody(byte[] reportBodyBytes, PublicKey publicKey, Date now) throws CertificateException {
        AttestationReportBody reportBody = AttestationReportBody.fromBytes(reportBodyBytes);
        String reportTimeUtcString = reportBody.timestamp.concat("+00:00");
        TemporalAccessor ta = DateTimeFormatter.ISO_INSTANT.parse(reportTimeUtcString);
        Instant i = Instant.from(ta);
        if (i.plus(this.reportValidityDuration).compareTo(now.toInstant()) > 0) {
            throw new CertificateException("Report expired");
        }
        List<EnclaveQuoteStatus> statuses = Arrays.stream(reportBody.isvEnclaveQuoteStatus.split(",")).map(EnclaveQuoteStatus::valueOf).collect(Collectors.toList());
        for (EnclaveQuoteStatus status : statuses) {
            if (!this.validEnclaveQuoteStatuses.contains(status)) {
                throw new CertificateException("Unexpected enclave quote status: " + status);
            }
        }
        try {
            Quote quote = Quote.parseFromBase64(reportBody.isvEnclaveQuoteBody);
            if (!quote.publicKeyMatches(publicKey)) {
                throw new CertificateException("Enclave quote public key mismatch");
            }
            return quote;
        } catch (ParseException e) {
            throw new CertificateException("Error parsing quote body", e);
        }
    }


    private PKIXCertPathBuilderResult verifyCertificates(List<X509Certificate> intermediateCerts, Date now) throws GeneralSecurityException {
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificateValid(now);
        PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(Collections.singleton(this.rootCert), selector);
        // Disable CRL checks (this is done manually as additional step)
        pkixBuilderParameters.setRevocationEnabled(false);
        // Specify a list of intermediate certificates
        CertStore intermediateCertStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(intermediateCerts));
        pkixBuilderParameters.addCertStore(intermediateCertStore);
        // Build and verify the certification chain
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
        return (PKIXCertPathBuilderResult) builder
                .build(pkixBuilderParameters);
    }

    private boolean verifyReportSignature(PublicKey endEntityPublicKey, byte[] reportBody, byte[] reportSignature) throws CertificateException {
        boolean isValid = verifySignature("SHA256withRSA", endEntityPublicKey, reportBody, reportSignature);
        if(!isValid) {
            isValid = verifySignature("SHA256withECDSA", endEntityPublicKey, reportBody, reportSignature);
        }
        return isValid;
    }

    private boolean verifySignature(String algorithm, PublicKey publicKey, byte[] message, byte[] signature) throws CertificateException {
        try {
            Signature rsa = Signature.getInstance(algorithm);
            rsa.initVerify(publicKey);
            rsa.update(message);
            return rsa.verify(signature);
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            throw new CertificateException("Could not verify signature");
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[]{this.rootCert.getTrustedCert()};
    }
}

