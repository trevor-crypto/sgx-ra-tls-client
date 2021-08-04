package tls;

import tls.types.Quote;

public interface QuoteVerifier {
    @SuppressWarnings("SameReturnValue")
    default boolean verify(Quote quote) {
        // does nothing
        return true;
    }
}
