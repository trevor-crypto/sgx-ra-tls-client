package com.cryptodotcom.types;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;

public class AttestationReport {
    public byte[] body;
    public byte[] signature;
    public byte[] signing_cert;

    public static AttestationReport fromBytes(byte[] reportBytes) throws JsonSyntaxException {
        Gson gson = new Gson();
        return gson.fromJson(new InputStreamReader(new ByteArrayInputStream(reportBytes)), AttestationReport.class);
    }
}
