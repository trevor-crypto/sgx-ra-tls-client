package tls;

import tls.types.Quote;

public interface QuoteVerifier {
    default boolean verify(Quote quote) {
        // does nothing
        return true;
    }
}
