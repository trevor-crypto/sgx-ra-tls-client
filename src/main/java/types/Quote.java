package types;

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

    public boolean publicKeyMatches(PublicKey publicKey) {
        byte[] pubkeyBytes = publicKey.getEncoded();
        boolean correctLength = pubkeyBytes.length == 65;
        boolean isUncompressed = pubkeyBytes[0] == 4;
        boolean matchesQuote = Arrays.equals(Arrays.copyOfRange(pubkeyBytes, 1, 64), this.report_body.report_data);
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
