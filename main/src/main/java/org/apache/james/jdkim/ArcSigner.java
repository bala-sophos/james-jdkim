/****************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one   *
 * or more contributor license agreements.  See the NOTICE file *
 * distributed with this work for additional information        *
 * regarding copyright ownership.  The ASF licenses this file   *
 * to you under the Apache License, Version 2.0 (the            *
 * "License"); you may not use this file except in compliance   *
 * with the License.  You may obtain a copy of the License at   *
 *                                                              *
 *   http://www.apache.org/licenses/LICENSE-2.0                 *
 *                                                              *
 * Unless required by applicable law or agreed to in writing,   *
 * software distributed under the License is distributed on an  *
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY       *
 * KIND, either express or implied.  See the License for the    *
 * specific language governing permissions and limitations      *
 * under the License.                                           *
 ****************************************************************/


package org.apache.james.jdkim;

import org.apache.james.jdkim.api.ArcValidationResult;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.impl.DNSPublicKeyRecordRetriever;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.jdkim.tagvalue.ArcSealSignatureRecordImpl;
import org.apache.james.jdkim.tagvalue.ArcSealSignatureRecordTemplate;
import org.apache.james.mime4j.MimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Map;

import static org.apache.james.jdkim.DKIMCommon.updateSignature;

public class ArcSigner
{
    Logger log = LoggerFactory.getLogger(ArcSigner.class);


    private final DKIMSigner dkimSigner;

    private final PrivateKey privateKey;
    public ArcSigner(String signatureRecordTemplate, PrivateKey privateKey)
    {
        dkimSigner = new DKIMSigner(signatureRecordTemplate, privateKey);
        this.privateKey = privateKey;
    }

    public String sign(InputStream is)
        throws IOException, FailException, MimeException
    {

        String signatureHeaderName = DKIMCommon.ARC_MESSAGE_SIGNATURE_HEADER;

        return dkimSigner.sign(is, signatureHeaderName);

    }

    public String seal(String ams, String aar, String sealTemplate,
                       Map<Integer, Map<String, String>> instances)
        throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        ArcSealSignatureRecordTemplate tvl = new ArcSealSignatureRecordTemplate(sealTemplate);
        Signature signature = Signature.getInstance(tvl.getHashMethod()
                                                       .toString().toUpperCase()
                                                    + "with" + tvl.getHashKeyType().toString().toUpperCase());

        signature.initSign(privateKey);

        for (int i = 1; i <= instances.size(); i++)
        {
            Map<String, String> instanceHeaders = instances.get(i);
            if (instanceHeaders.containsKey("arc-authentication-results")) {
                String fv = "arc-authentication-results" + ":" + instanceHeaders.get("arc-authentication-results");
                updateSignature(signature, true, "arc-authentication-results",
                                fv);
                signature.update("\r\n".getBytes());
            }

            if (instanceHeaders.containsKey("arc-message-signature")) {

                String fv = "arc-message-signature" + ":" + instanceHeaders.get("arc-message-signature");
                updateSignature(signature, true, "arc-message-signature",
                                fv);
                signature.update("\r\n".getBytes());
            }

            // Include ARC-Seal for previous instances, but not the current one being verified
            if (instanceHeaders.containsKey("arc-seal")) {
                String fv = "arc-seal"+ ":" + instanceHeaders.get("arc-seal");
                updateSignature(signature, true, "arc-seal",
                                fv);
                signature.update("\r\n".getBytes());
            }


        }

        updateSignature(signature, true, "arc-authentication-results", "arc-authentication-results" + ":" + aar);
        signature.update("\r\n".getBytes());

        updateSignature(signature, true, "arc-message-signature", "arc-message-signature" + ":" + ams);
        signature.update("\r\n".getBytes());

        updateSignature(signature, true, "arc-seal", "arc-seal" + ":" + tvl.toUnsignedString());
        tvl.setSignature(signature.sign());

        return "Arc-Seal" + ":" + tvl.toString();
    }

}
