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

import org.apache.james.jdkim.ArcSigner;
import org.apache.james.jdkim.ArcVerifier;
import org.apache.james.jdkim.TestKeys;
import org.apache.james.jdkim.api.ArcValidationResult;
import org.apache.james.jdkim.impl.DNSPublicKeyRecordRetriever;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.mime4j.MimeException;
import org.junit.Assert;
import org.junit.Test;
import java.util.Map;
import java.util.HashMap;

import java.io.IOException;

public class ArcTest
{
    @Test
    public void testArcValidationPass()
        throws MimeException, IOException
    {
        ArcVerifier validator = new ArcVerifier(new DNSPublicKeyRecordRetriever());
        Message message = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_pass.eml"));

        Assert.assertEquals(ArcValidationResult.Status.PASS, validator.validate(message).getStatus());

        message = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_pass_2.eml"));

        Assert.assertEquals(ArcValidationResult.Status.PASS, validator.validate(message).getStatus());
    }


    @Test
    public void testArcValidationFail()
        throws MimeException, IOException
    {
        ArcVerifier validator = new ArcVerifier(new DNSPublicKeyRecordRetriever());
        Message message = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_fail.eml"));

        Assert.assertEquals(ArcValidationResult.Status.FAIL, validator.validate(message).getStatus());
    }

    @Test
    public void testArcSealGeneration()
        throws Exception
    {
        ArcVerifier validator = new ArcVerifier(new DNSPublicKeyRecordRetriever());
        Message message = new Message(ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_pass.eml"));

        ArcValidationResult result = validator.validate(message);

        int instance = result.getInstanceCount() + 1;

        String signatureTemple = "i="+instance +"; a=rsa-sha256; c=relaxed/relaxed; d=g-suite1.emailblr1.com; h=date:from:subject; q=dns/txt; s=sophos100;";

        ArcSigner signer = new ArcSigner(signatureTemple, TestKeys.arc_privatekey_1);

        String ams = signer.sign(ArcTest.class.getResourceAsStream("/org/apache/james/arc/arc_pass.eml"));

        String aar = "ARC-Authentication-Results: i=5; mx.g-suite1.emailblr1.com;"
                     + " dkim=pass header.i=@gmail.com header.s=20230601 header.b=\"QzZwwS/+\";"
                     + " spf=pass (google.com: domain of rohullahrahmanee@gmail.com designates 209.85.216.41 as permitted sender) smtp.mailfrom=rohullahrahmanee@gmail.com;";


        String sealTemplate = "a=rsa-sha256; b=; cv=pass; s=sophos100; d=g-suite1.emailblr1.com; i="+ instance +";";


        String as = signer.seal(ams.substring(ams.indexOf(":")+1),
                                aar.substring(aar.indexOf(":")+1) ,
                                sealTemplate, result.getAllInstances());


        Map<Integer, Map<String, String>> instances = result.getAllInstances();
        instances.put(instance, new HashMap<>());
        instances.get(instance).put("arc-seal", as.substring(as.indexOf(":")+1));
        instances.get(instance).put("arc-message-signature", ams.substring(ams.indexOf(":")+1));
        instances.get(instance).put("arc-authentication-results", aar.substring(aar.indexOf(":")+1));

        boolean sealValid = validator.verifyArcSeal(as.substring(as.indexOf(":")+1),instances, instance);

        Assert.assertTrue(sealValid);

    }
}