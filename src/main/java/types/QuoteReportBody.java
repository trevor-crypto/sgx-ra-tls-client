package types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.text.ParseException;
import java.util.Arrays;

public class QuoteReportBody {
    private static final int LENGTH = 384;

    public byte[] cpu_svn = new byte[16];
    public byte[] attributes = new byte[16];
    public byte[] mr_signer = new byte[32];
    public byte[] mr_enclave = new byte[32];
    public short isv_prod_id;
    public short isv_svn;
    public byte[] report_data = new byte[64];

    public static QuoteReportBody fromBytes(byte[] bytes) throws ParseException {
        if(bytes.length != QuoteReportBody.LENGTH) {
            throw new ParseException(String.format("Quote report body is not required length, got %d, required %d", bytes.length, QuoteReportBody.LENGTH), 0);
        }
        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        QuoteReportBody reportBody = new QuoteReportBody();
        buffer.get(reportBody.cpu_svn, 0, 16);
        buffer.get(reportBody.attributes, 0, 16);
        buffer.get(reportBody.mr_signer, 0, 32);
        buffer.get(reportBody.mr_enclave, 0, 32);
        reportBody.isv_prod_id = buffer.getShort();
        reportBody.isv_svn = buffer.getShort();
        reportBody.report_data = buffer.slice().array();
        return reportBody;
    }

    @Override
    public String toString() {
        return "QuoteReportBody{" +
                "cpu_svn=" + Arrays.toString(cpu_svn) +
                ", attributes=" + Arrays.toString(attributes) +
                ", mr_signer=" + Arrays.toString(mr_signer) +
                ", mr_enclave=" + Arrays.toString(mr_enclave) +
                ", isv_prod_id=" + isv_prod_id +
                ", isv_svn=" + isv_svn +
                ", report_data=" + Arrays.toString(report_data) +
                '}';
    }
}
