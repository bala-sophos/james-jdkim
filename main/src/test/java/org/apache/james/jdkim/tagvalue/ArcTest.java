package org.apache.james.jdkim.tagvalue;

import org.apache.james.jdkim.ArcSigner;
import org.apache.james.jdkim.ArcVerifier;
import org.apache.james.jdkim.DKIMVerifier;
import org.apache.james.jdkim.TestKeys;
import org.apache.james.jdkim.api.ArcValidationResult;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.impl.DNSPublicKeyRecordRetriever;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.mime4j.MimeException;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.List;

public class ArcTest
{
    @Test
    public void testArcValidationPass()
        throws MimeException, IOException
    {
        ArcVerifier validator = new ArcVerifier(new DNSPublicKeyRecordRetriever());
        Message message = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/jdkim/corpus/arc_pass.eml"));

        Assert.assertEquals(ArcValidationResult.Status.PASS, validator.validate(message).getStatus());
    }


    @Test
    public void testArcValidationFail()
        throws MimeException, IOException
    {
        ArcVerifier validator = new ArcVerifier(new DNSPublicKeyRecordRetriever());
        Message message = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/jdkim/corpus/arc_fail.eml"));

        Assert.assertEquals(ArcValidationResult.Status.FAIL, validator.validate(message).getStatus());
    }

    @Test
    public void testArcMessageSignatureGeneration()
        throws Exception
    {
        ArcVerifier validator = new ArcVerifier(new DNSPublicKeyRecordRetriever());
        Message message = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/jdkim/corpus/arc_pass.eml"));

        ArcValidationResult result = validator.validate(message);

        int instance = result.getInstanceCount() + 1;

        String signatureTemple = "i="+instance +"; a=rsa-sha256; c=relaxed/relaxed; d=g-suite1.emailblr1.com; h=date:from:subject; q=dns/txt; s=sophos100;";

        ArcSigner signer = new ArcSigner(signatureTemple, TestKeys.arc_privatekey_1);

        String ams = signer.sign(ArcTest.class.getResourceAsStream("/org/apache/james/jdkim/corpus/arc_pass.eml"));

        message = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/jdkim/corpus/arc_pass.eml"));

        ArcVerifier verifier = new ArcVerifier(new DNSPublicKeyRecordRetriever());

        boolean isValid = verifier.verifyArcMessageSignature(message, ams);

        System.out.println("Is Valid: " + isValid);

        message = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/jdkim/corpus/arc_fail.eml"));
        verifier = new ArcVerifier(new DNSPublicKeyRecordRetriever());
        isValid = verifier.verifyArcMessageSignature(message, ams);
        System.out.println("Is Valid: " + isValid);
    }


}
