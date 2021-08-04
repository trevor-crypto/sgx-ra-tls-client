package com.cryptodotcom.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.text.ParseException;
import java.util.Arrays;

public class QuoteBody {
    private static final int LENGTH = 48;

    public short version;
    public short sig_type;
    public int gid;
    public short qe_svn;
    public short pce_svn;
    public final byte[] basename = new byte[32];

    public static QuoteBody fromBytes(byte[] bytes) throws ParseException {
        if(bytes.length != QuoteBody.LENGTH) {
            throw new ParseException(String.format("Quote body is not required length, got %d, required %d", bytes.length, QuoteBody.LENGTH), 0);
        }
        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        QuoteBody quoteBody = new QuoteBody();
        quoteBody.version = buffer.getShort();
        quoteBody.sig_type = buffer.getShort();
        quoteBody.gid = buffer.getInt();
        quoteBody.qe_svn = buffer.getShort();
        quoteBody.pce_svn = buffer.getShort();
        buffer.position(buffer.position() + 4);
        buffer.get(quoteBody.basename);
        return quoteBody;
    }

    @Override
    public String toString() {
        return "QuoteBody{" +
                "version=" + version +
                ", sig_type=" + sig_type +
                ", gid=" + gid +
                ", qe_svn=" + qe_svn +
                ", pce_svn=" + pce_svn +
                ", basename=" + Arrays.toString(basename) +
                '}';
    }
}
