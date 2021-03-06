package com.cryptodotcom.types;

public enum EnclaveQuoteStatus {
    OK,
    SIGNATURE_INVALID,
    GROUP_REVOKED,
    SIGNATURE_REVOKED,
    KEY_REVOKED,
    SIGRL_VERSION_MISMATCH,
    GROUP_OUT_OF_DATE,
    CONFIGURATION_NEEDED,
    SW_HARDENING_NEEDED,
    CONFIGURATION_AND_SW_HARDENING_NEEDED
}
