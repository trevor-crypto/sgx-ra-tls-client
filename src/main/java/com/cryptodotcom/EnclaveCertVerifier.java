package com.cryptodotcom;

import com.cryptodotcom.types.AttestationReport;
import com.cryptodotcom.types.AttestationReportBody;
import com.cryptodotcom.types.EnclaveQuoteStatus;
import com.cryptodotcom.types.Quote;
import org.bouncycastle.asn1.ASN1OctetString;

import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

public class EnclaveCertVerifier implements X509TrustManager {
    private final Set<EnclaveQuoteStatus> validEnclaveQuoteStatuses;
    private final TrustAnchor rootCert;
    private final Duration reportValidityDuration;
    private final QuoteVerifier quoteVerifier;

    private static final String OID_EXTENSION_ATTESTATION_REPORT = "2.16.840.1.113730.1.13";

    /**
     * @param validQuotes Valid enclave quote statuses
     * @param reportValidityDuration Validity duration of enclave quote
     * @throws CertificateException When the CA cert can't be parsed
     * @throws IOException Should never occur since resource is bundled with library
     */
    public EnclaveCertVerifier(Set<EnclaveQuoteStatus> validQuotes, Duration reportValidityDuration) throws CertificateException, IOException, URISyntaxException {
        this(validQuotes, new QuoteVerifier() {}, reportValidityDuration);
    }

    /**
     * @param validQuotes Valid enclave quote statuses
     * @param quoteVerifier A custom verifier to verify values in an enclave quote
     * @param reportValidityDuration Validity duration of enclave quote
     * @throws CertificateException When the CA cert can't be parsed
     * @throws IOException Should never occur since resource is bundled with library
     */
    public EnclaveCertVerifier(Set<EnclaveQuoteStatus> validQuotes, QuoteVerifier quoteVerifier, Duration reportValidityDuration) throws CertificateException, IOException, URISyntaxException {
        ClassLoader classLoader = this.getClass().getClassLoader();
        byte[] cert = Files.readAllBytes(Paths.get(classLoader.getResource("AttestationReportSigningCACert.der").toURI()));
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate rootCert = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(cert));

        this.rootCert = new TrustAnchor(rootCert, null);
        this.validEnclaveQuoteStatuses = validQuotes;
        this.quoteVerifier = quoteVerifier;
        this.reportValidityDuration = reportValidityDuration;
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
            byte[] publicKey = getPublicKeyBytes(cert.getPublicKey());
            byte[] reportDerOctet = cert.getExtensionValue(OID_EXTENSION_ATTESTATION_REPORT);
            byte[] reportBytes = ASN1OctetString.getInstance(reportDerOctet).getOctets();

            // Verify attestation report
            verifyAttestationReport(reportBytes, publicKey, now);
        }
    }

    protected Quote verifyAttestationReport(byte[] reportBytes, byte[] publicKey, Date now) throws CertificateException {
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
            throw new CertificateException("Couldn't verify certificate chain", e);
        }

        PublicKey endEntityPublicKey = endEntityCert.getPublicKey();
        boolean isValid = verifyReportSignature(endEntityPublicKey, attestationReport.body, attestationReport.signature);
        if(!isValid) {
            throw new CertificateException("Attestation report signature invalid");
        }

        return verifyAttestationReportBody(attestationReport.body, publicKey, now);
    }

    private Quote verifyAttestationReportBody(byte[] reportBodyBytes, byte[] publicKey, Date now) throws CertificateException {
        AttestationReportBody reportBody = AttestationReportBody.fromBytes(reportBodyBytes);
        String reportTimeUtcString = reportBody.timestamp.concat("+00:00");
        Instant reportTime = Instant.from(DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(reportTimeUtcString));
        if (reportTime.plus(this.reportValidityDuration).isBefore(now.toInstant())) {
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

            // Do actual quote verification, like checking measurements
            if(!this.quoteVerifier.verify(quote)) {
                throw new CertificateException("Quote verification failed");
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

    private byte[] getPublicKeyBytes(PublicKey publicKey) throws CertificateException {
        int PUB_KEY_SIZE = 65;
        if(publicKey instanceof ECPublicKey) {
            ECPoint point = ((ECPublicKey) publicKey).getW();
            byte[] x = point.getAffineX().toByteArray();
            x[0] = 4;
            byte[] y = point.getAffineY().toByteArray();
            if(x.length + y.length != PUB_KEY_SIZE) {
                throw new CertificateException("Public key parts incorrect size");
            }
            ByteBuffer buffer = ByteBuffer.allocate(PUB_KEY_SIZE);
            buffer.put(x);
            buffer.put(y);
            return buffer.array();
        } else {
            throw new CertificateException("Public key not EC key");
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[]{this.rootCert.getTrustedCert()};
    }
}

