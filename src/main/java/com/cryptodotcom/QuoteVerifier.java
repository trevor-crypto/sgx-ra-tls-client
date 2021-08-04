package com.cryptodotcom;

import com.cryptodotcom.types.Quote;

public interface QuoteVerifier {
    @SuppressWarnings("SameReturnValue")
    default boolean verify(Quote quote) {
        // does nothing
        return true;
    }
}
