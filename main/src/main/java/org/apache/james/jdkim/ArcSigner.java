package org.apache.james.jdkim;

import org.apache.james.jdkim.api.ArcValidationResult;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.impl.DNSPublicKeyRecordRetriever;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.mime4j.MimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;

public class ArcSigner
{
    Logger log = LoggerFactory.getLogger(ArcSigner.class);
    private final DKIMSigner dkimSigner;
    public ArcSigner(String signatureRecordTemplate, PrivateKey privateKey)
    {
        dkimSigner = new DKIMSigner(signatureRecordTemplate, privateKey);
    }

    public String sign(InputStream is)
        throws IOException, FailException, MimeException
    {

        String signatureHeaderName = "ARC-Message-Signature";

        return dkimSigner.sign(is, signatureHeaderName);

    }

}
