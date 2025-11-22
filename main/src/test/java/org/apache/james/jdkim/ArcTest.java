/******************************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one                 *
 * or more contributor license agreements.  See the NOTICE file               *
 * distributed with this work for additional information                      *
 * regarding copyright ownership.  The ASF licenses this file                 *
 * to you under the Apache License, Version 2.0 (the                          *
 * "License"); you may not use this file except in compliance                 *
 * with the License.  You may obtain a copy of the License at                 *
 *                                                                            *
 *   http://www.apache.org/licenses/LICENSE-2.0                               *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing,                 *
 * software distributed under the License is distributed on an                *
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY                     *
 * KIND, either express or implied.  See the License for the                  *
 * specific language governing permissions and limitations                    *
 * under the License.                                                         *
 ******************************************************************************/

package org.apache.james.jdkim;

import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeUtility;
import org.apache.james.jdkim.api.ArcValidationResult;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.impl.BodyHasherImpl;
import org.apache.james.jdkim.impl.DNSPublicKeyRecordRetriever;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.jdkim.tagvalue.ArcMessageSignatureRecordImpl;
import org.apache.james.jdkim.tagvalue.ArcMessageSignatureRecordTemplate;
import org.apache.james.mime4j.MimeException;
import org.apache.james.mime4j.io.EOLConvertingInputStream;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.james.jdkim.DKIMCommon.AAR_HEADER;
import static org.apache.james.jdkim.DKIMCommon.AMS_HEADER;
import static org.apache.james.jdkim.DKIMCommon.AS_HEADER;
import static org.assertj.core.api.Assertions.assertThat;

public class ArcTest
{
    @Test
    public void testArcValidationPass()
        throws MimeException, IOException, FailException
    {
        ArcVerifier validator = new ArcVerifier(new DNSPublicKeyRecordRetriever());
        Message message = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_pass.eml"));
        Map<Integer, Map<String, String>> instances = validator.groupArcHeadersByInstance(message.getFields());

        Assert.assertEquals(ArcValidationResult.Status.PASS, validator.validate(message,
                                                                                instances,
                                                                                getBodyHasher(message, instances)).getStatus());

        message = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_pass_2.eml"));
        instances = validator.groupArcHeadersByInstance(message.getFields());

        Assert.assertEquals(ArcValidationResult.Status.PASS, validator.validate(message,
                                                                                instances,
                                                                                getBodyHasher(message, instances)).getStatus());
    }


    @Test
    public void testArcValidationFail()
        throws MimeException, IOException, FailException
    {
        ArcVerifier validator = new ArcVerifier(new DNSPublicKeyRecordRetriever());
        Message message = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_fail.eml"));
        Map<Integer, Map<String, String>> instances = validator.groupArcHeadersByInstance(message.getFields());
        Assert.assertEquals(ArcValidationResult.Status.FAIL, validator.validate(message,
                                                                                instances,
                                                                                getBodyHasher(message, instances)).getStatus());
    }

    @Test
    public void testArcSealGeneration()
        throws Exception
    {
        ArcVerifier validator = new ArcVerifier(new DNSPublicKeyRecordRetriever());
        Message message = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_pass.eml"));
        Map<Integer, Map<String, String>> instances = validator.groupArcHeadersByInstance(message.getFields());

        ArcValidationResult result = validator.validate(message,
                                                        instances,
                                                        getBodyHasher(message, instances));



        int instance = result.getInstanceCount() + 1;

        String signatureTemplate = "i="+instance +"; a=rsa-sha256; c=relaxed/relaxed; d=g-suite1.emailblr1.com; h=date:from:subject; q=dns/txt; s=sophos100;";

        ArcSigner signer = new ArcSigner(TestKeys.arc_privatekey_1);

        String ams = signer.sign(ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_pass.eml"),
                                 signatureTemplate);

        String aar = "i="+ instance + "; mx.g-suite1.emailblr1.com;"
                     + " dkim=pass header.i=@gmail.com header.s=20230601 header.b=\"QzZwwS/+\";"
                     + " spf=pass (google.com: domain of rohullahrahmanee@gmail.com designates 209.85.216.41 as permitted sender) smtp.mailfrom=rohullahrahmanee@gmail.com;";


        String sealTemplate =  "i="+ instance + "; a=rsa-sha256; b=; cv=pass; s=sophos100; d=g-suite1.emailblr1.com;";

        String as = signer.seal(ams,
                                aar,
                                sealTemplate, instances);

        instances.put(instance, new HashMap<>());
        instances.get(instance).put("arc-seal", as);
        instances.get(instance).put("arc-message-signature", ams);
        instances.get(instance).put("arc-authentication-results", aar);

        boolean sealValid = validator.verifyArcSeal(as, instances);

        Assert.assertTrue(sealValid);

        System.out.println("Messages with new ARC headers:");

        MimeMessage mimeMessage = new MimeMessage(null, ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_pass.eml"));
        mimeMessage.addHeader(AMS_HEADER, MimeUtility.fold(23, ams));
        mimeMessage.addHeader(AAR_HEADER, MimeUtility.fold(23, aar));
        mimeMessage.addHeader(AS_HEADER, MimeUtility.fold(23, as));

        mimeMessage.saveChanges();

        mimeMessage.writeTo(System.out);
    }

    @Test
    public void testBothSigningMethodsProduceSameSignature() throws Exception {
        String signatureTemplate = "i=3; a=rsa-sha256; c=relaxed/relaxed; d=g-suite1.emailblr1.com; h=date:from:subject; q=dns/txt; s=sophos100;";
        ArcSigner signer = new ArcSigner(TestKeys.arc_privatekey_1);
        String ams1 = signer.sign(ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_pass.eml"),
                                  signatureTemplate);

        ArcMessageSignatureRecordTemplate signatureRecord = new ArcMessageSignatureRecordTemplate(signatureTemplate);

        BodyHasherImpl bodyHasher =  new BodyHasherImpl(signatureRecord);

        Message message = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_pass.eml"));

        byte[] buffer = new byte[2048];
        int read;

        try (InputStream bodyStream = message.getBodyInputStream();
             OutputStream hashOutputStream = bodyHasher.getOutputStream()) {
            while ((read = bodyStream.read(buffer)) > 0) {
                hashOutputStream.write(buffer, 0, read);
            }
        }

        String ams2 = signer.sign(message, signatureTemplate, bodyHasher.getDigest());

        // Verify both signatures are identical
        assertThat(ams1)
            .as("Both signing methods should produce identical signatures")
            .isEqualTo(ams2);

        System.out.println("Generated signature using sign(InputStream is):");
        System.out.println(ams1);
        System.out.println("\nGenerated signature using sign(Headers message, BodyHasher bh):");
        System.out.println(ams2);
        System.out.println("\n✓ Both signatures are identical!");
    }

    @Test
    public void testArcSealGenerationWithBothJdkimMessageAndMimeMessage()
        throws Exception
    {
        String signatureTemplate = "i=3; a=rsa-sha256; c=relaxed/relaxed; d=g-suite1.emailblr1.com; h=date:from:subject; q=dns/txt; s=sophos100;";
        String sealTemplate = "i=3; a=rsa-sha256; b=; cv=pass; s=sophos100; d=g-suite1.emailblr1.com;";
        String aar = "i=3; mx.g-suite1.emailblr1.com;"
                     + " dkim=pass header.i=@gmail.com header.s=20230601 header.b=\"QzZwwS/+\";"
                     + " spf=pass (google.com: domain of rohullahrahmanee@gmail.com designates 209.85.216.41 as permitted sender) smtp.mailfrom=rohullahrahmanee@gmail.com;";


        ArcMessageSignatureRecordTemplate signatureRecord = new ArcMessageSignatureRecordTemplate(signatureTemplate);
        ArcSigner signer = new ArcSigner(TestKeys.arc_privatekey_1);
        ArcVerifier validator = new ArcVerifier(new DNSPublicKeyRecordRetriever());


        Message message1 = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_pass.eml"));
        BodyHasherImpl bodyHasher1 =  new BodyHasherImpl(signatureRecord);

        byte[] buffer = new byte[2048];
        int read;

        try (InputStream bodyStream = message1.getBodyInputStream();
             OutputStream hashOutputStream = bodyHasher1.getOutputStream()) {
            while ((read = bodyStream.read(buffer)) > 0) {
                hashOutputStream.write(buffer, 0, read);
            }
        }


        String ams1 = signer.sign(message1, signatureTemplate, bodyHasher1.getDigest());

        Map<Integer, Map<String, String>> instances1 = validator.groupArcHeadersByInstance(message1.getFields());


        String seal1  = signer.seal(ams1,
                                    aar, sealTemplate, instances1);

        System.out.println("Generate AMS using JDKIM Message:" + ams1);
        System.out.println("Generated ARC-Seal using JDKIM Message:" + seal1);

        instances1.put(3, new HashMap<>());
        instances1.get(3).put("arc-seal", seal1);
        instances1.get(3).put("arc-message-signature", ams1);
        instances1.get(3).put("arc-authentication-results", aar);

        boolean sealValid = validator.verifyArcSeal(seal1, instances1);

        Assert.assertTrue(sealValid);

        MimeMessage mimeMessage = new MimeMessage(null, ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_pass.eml"));
        BodyHasherImpl bodyHasher2 =  new BodyHasherImpl(signatureRecord);

        try(InputStream bodyStream = new EOLConvertingInputStream(mimeMessage.getRawInputStream());
            OutputStream hashOutputStream = bodyHasher2.getOutputStream()) {
            while ((read = bodyStream.read(buffer)) > 0) {
                hashOutputStream.write(buffer, 0, read);
            }
        }

        List<String> headerLines = new ArrayList<>();
        Enumeration<String> headerEnum = mimeMessage.getAllHeaderLines();
        while(headerEnum.hasMoreElements())
        {
            headerLines.add(headerEnum.nextElement());
        }

        String ams2 = signer.sign(new Headers()
        {
            @Override
            public List<String> getFields()
            {
                return headerLines;
            }

            @Override
            public List<String> getFields(String s)
            {
                List<String> result = new ArrayList<>();
                String headerPrefix = s.toLowerCase() + ":";

                for (String header : headerLines)
                {
                    if (header.toLowerCase().startsWith(headerPrefix))
                    {
                        result.add(header);
                    }
                }

                return result;
            }
        }, signatureTemplate, bodyHasher2.getDigest());

        Map<Integer, Map<String, String>> instances2 = validator.groupArcHeadersByInstance(headerLines);


        String seal2  = signer.seal(ams2,
                                    aar, sealTemplate, instances2);

        System.out.println("Generate AMS using MIME Message:" + ams2);
        System.out.println("Generated ARC-Seal using MIME Message:" + seal2);

        instances2.put(5, new HashMap<>());
        instances2.get(5).put("arc-seal", seal2);
        instances2.get(5).put("arc-message-signature", ams2);
        instances2.get(5).put("arc-authentication-results", aar);

        Assert.assertEquals(ams1, ams2);
        Assert.assertEquals(seal1, seal2);
    }

    private BodyHasherImpl getBodyHasher(Message message,
                                 Map<Integer, Map<String, String>> instances) throws IOException, FailException
    {
        int instancesCount = instances.size();
        SignatureRecord signatureRecord =
            new ArcMessageSignatureRecordImpl(instances.get(instancesCount).get("arc-message-signature"));
        BodyHasherImpl bodyHasher =  new BodyHasherImpl(signatureRecord);
        byte[] buffer = new byte[2048];
        int read;
        try (InputStream bodyStream = message.getBodyInputStream();
             OutputStream hashOutputStream = bodyHasher.getOutputStream()) {
            while ((read = bodyStream.read(buffer)) > 0) {
                hashOutputStream.write(buffer, 0, read);
            }
        }

        return bodyHasher;
    }
}