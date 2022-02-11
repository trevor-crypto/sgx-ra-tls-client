# sgx-ra-tls-client
X509TrustManager client for talking to SGX enclaves over TLS

# Description
This library will allow a Java or Kotlin application to create a TLS connection with an SGX enclave. 

It exports an `EnclaveCertVerifier` (implements X509TrustManager) class that will verify the chain of certificates that were created 
during remote attestation.

Please see [this Kotlin example](https://github.com/trevor-crypto/sgx-tls-client-example) for basic usage.
