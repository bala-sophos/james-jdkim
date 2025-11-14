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
import org.apache.james.jdkim.api.BodyHasher;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.impl.BodyHasherImpl;
import org.apache.james.jdkim.impl.DNSPublicKeyRecordRetriever;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.jdkim.tagvalue.ArcMessageSignatureRecordTemplate;
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
import java.util.List;
import java.util.Map;

import static org.apache.james.jdkim.DKIMCommon.updateSignature;

public class ArcSigner
{
    Logger log = LoggerFactory.getLogger(ArcSigner.class);

    private final PrivateKey privateKey;
    public ArcSigner(PrivateKey privateKey)
    {
        this.privateKey = privateKey;
    }

    public String sign(InputStream is,
                       String arcMessageSignatureRecordTemplate)
        throws IOException, FailException
    {

        try
        {
            Message message = new Message(is);
            SignatureRecord signatureRecord = new ArcMessageSignatureRecordTemplate(arcMessageSignatureRecordTemplate);
            BodyHasher bodyHasher =  new BodyHasherImpl(signatureRecord);
            DKIMCommon.streamCopy(message.getBodyInputStream(), bodyHasher.getOutputStream());
            BodyHasherImpl bhj = (BodyHasherImpl) bodyHasher;
            signatureRecord.setBodyHash(bhj.getDigest());
            return sign(message, signatureRecord);
        }
        catch(MimeException e)
        {
            throw new PermFailException("MIME parsing exception: "
                                        + e.getMessage(), e);
        }
    }
    public String sign(Headers headers,
                       String arcMessageSignatureRecordTemplate,
                       byte[] bodyHash)
        throws PermFailException
    {
        SignatureRecord signatureRecord = new ArcMessageSignatureRecordTemplate(arcMessageSignatureRecordTemplate);
        signatureRecord.setBodyHash(bodyHash);
        return sign(headers, signatureRecord);
    }
    private String sign(Headers headers,
                       SignatureRecord signatureRecord)
        throws PermFailException
    {

        List<CharSequence> headersToIncludeInSignature = signatureRecord.getHeaders();

        try
        {
            Signature signature = Signature.getInstance(signatureRecord.getHashMethod()
                                                                                         .toString().toUpperCase()
                                                        + "with" + signatureRecord.getHashKeyType().toString().toUpperCase());
            signature.initSign(privateKey);

            DKIMCommon.signatureCheck(headers, signatureRecord,
                                     headersToIncludeInSignature, signature,
                                     DKIMCommon.ARC_MESSAGE_SIGNATURE_HEADER);

            byte[] signatureHash = signature.sign();
            signatureRecord.setSignature(signatureHash);
            return DKIMCommon.ARC_MESSAGE_SIGNATURE_HEADER + ":" + signatureRecord;
        }
        catch (InvalidKeyException e) {
            throw new PermFailException("Invalid key: " + e.getMessage(), signatureRecord, e);
        } catch (NoSuchAlgorithmException e) {
            throw new PermFailException("Unknown algorythm: " + e.getMessage(), signatureRecord,
                                        e);
        } catch (SignatureException e) {
            throw new PermFailException("Signing exception: " + e.getMessage(), signatureRecord,
                                        e);
        }


    }
    public String seal(String ams, String aar, String arcSealTempalte,
                       Map<Integer, Map<String, String>> instances)
        throws PermFailException
    {
        SignatureRecord tvl = new ArcSealSignatureRecordTemplate(arcSealTempalte);
        try
        {
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

            return DKIMCommon.ARC_SEAL_HEADER + ":" + tvl;
        }
        catch (InvalidKeyException e) {
            throw new PermFailException("Invalid key: " + e.getMessage(), tvl, e);
        } catch (NoSuchAlgorithmException e) {
            throw new PermFailException("Unknown algorythm: " + e.getMessage(), tvl,
                                        e);
        } catch (SignatureException e) {
            throw new PermFailException("Signing exception: " + e.getMessage(), tvl,
                                        e);
        }
    }

}
