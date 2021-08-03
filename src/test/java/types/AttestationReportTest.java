package types;

import com.google.gson.Gson;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.text.ParseException;
import java.util.Arrays;

class AttestationReportTest {

    @Test
    void canDeserialize() throws FileNotFoundException, ParseException {
        ClassLoader classLoader = this.getClass().getClassLoader();
        File file = new File(classLoader.getResource("valid_attestation_report.json").getFile());
        FileReader fileReader = new FileReader(file);
        Gson gson = new Gson();
        AttestationReport report = gson.fromJson(fileReader, AttestationReport.class);

        System.out.println("report body: " + Arrays.toString(report.body));
        System.out.println("report sig: " + Arrays.toString(report.signature));
        System.out.println("report signing_cert: " + Arrays.toString(report.signing_cert));

        AttestationReportBody reportBody = gson.fromJson(new InputStreamReader(new ByteArrayInputStream(report.body)), AttestationReportBody.class);
        System.out.println(reportBody.toString());

        System.out.println("Quote: " + reportBody.getQuote().toString());
    }
}