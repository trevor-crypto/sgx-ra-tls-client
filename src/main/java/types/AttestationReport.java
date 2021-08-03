package types;

import com.google.gson.Gson;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;

public class AttestationReport {
    public byte[] body;
    public byte[] signature;
    public byte[] signing_cert;

    public static AttestationReport fromBytes(byte[] reportBytes) {
        Gson gson = new Gson();
        return gson.fromJson(new InputStreamReader(new ByteArrayInputStream(reportBytes)), AttestationReport.class);
    }
}
