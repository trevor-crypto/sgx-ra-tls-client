package types;

public enum EnclaveQuoteStatus {
    Ok("OK"),
    SignatureInvalid("SIGNATURE_INVALID"),
    GroupRevoked("GROUP_REVOKED"),
    SignatureRevoked("SIGNATURE_REVOKED"),
    KeyRevoked("KEY_REVOKED"),
    SigrlVersionMismatch("SIGRL_VERSION_MISMATCH"),
    GroupOutOfDate("GROUP_OUT_OF_DATE"),
    ConfigurationNeeded("CONFIGURATION_NEEDED"),
    SwHardeningNeeded("SW_HARDENING_NEEDED"),
    ConfigurationAndSwHardeningNeeded("CONFIGURATION_AND_SW_HARDENING_NEEDED");

    private String value;

    EnclaveQuoteStatus(String value) {
        this.value = value;
    }

    public String getValue() {
        return this.value;
    }
}
