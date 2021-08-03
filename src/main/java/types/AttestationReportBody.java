package types;

import com.google.gson.Gson;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.text.ParseException;

public class AttestationReportBody {
    public String id;
    public String timestamp;
    public byte version;
    public String isvEnclaveQuoteStatus;
    public String isvEnclaveQuoteBody;
    public int revocationReason;
    public String pseManifestStatus;
    public String pseManifestHash;
    public String platformInfoBlob;
    public String nonce;
    public String epidPseudonym;
    public String advisoryURL;
    public String[] advisoryIDs;

    public Quote getQuote() throws ParseException {
        return Quote.parseFromBase64(this.isvEnclaveQuoteBody);
    }

    public static AttestationReportBody fromBytes(byte[] reportBytes) {
        Gson gson = new Gson();
        return gson.fromJson(new InputStreamReader(new ByteArrayInputStream(reportBytes)), AttestationReportBody.class);
    }

    @Override
    public String toString() {
        return "AttestationReportBody{" +
                "id='" + id + '\'' +
                ", timestamp='" + timestamp + '\'' +
                ", version=" + version +
                ", isvEnclaveQuoteStatus='" + isvEnclaveQuoteStatus + '\'' +
                ", isvEnclaveQuoteBody='" + isvEnclaveQuoteBody + '\'' +
                ", revocationReason=" + revocationReason +
                ", pseManifestStatus='" + pseManifestStatus + '\'' +
                ", pseManifestHash='" + pseManifestHash + '\'' +
                ", platformInfoBlob='" + platformInfoBlob + '\'' +
                ", nonce='" + nonce + '\'' +
                ", epidPseudonym='" + epidPseudonym + '\'' +
                ", advisoryURL='" + advisoryURL + '\'' +
                ", advisoryIDs='" + advisoryIDs + '\'' +
                '}';
    }
}
