package tls.types;

import java.security.PublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;

public class Quote {
    public QuoteBody body;
    public QuoteReportBody report_body;

    public static Quote parseFromBase64(String isvEnclaveQuoteBody) throws ParseException {
        byte[] quoteBytes = Base64.getDecoder().decode(isvEnclaveQuoteBody);
        byte[] quoteBodyBytes = Arrays.copyOfRange(quoteBytes, 0, 48);
        byte[] quoteReportBodyBytes = Arrays.copyOfRange(quoteBytes, 48, 432);
        Quote quote = new Quote();
        quote.body = QuoteBody.fromBytes(quoteBodyBytes);
        quote.report_body = QuoteReportBody.fromBytes(quoteReportBodyBytes);
        return quote;
    }

    public boolean publicKeyMatches(byte[] publicKey) {
        boolean correctLength = publicKey.length == 65;
        boolean isUncompressed = publicKey[0] == 4;
        boolean matchesQuote = Arrays.equals(Arrays.copyOfRange(publicKey, 1, 65), this.report_body.report_data);
        return correctLength && isUncompressed && matchesQuote;
    }

    @Override
    public String toString() {
        return "Quote{" +
                "body=" + body +
                ", report_body=" + report_body +
                '}';
    }
}
