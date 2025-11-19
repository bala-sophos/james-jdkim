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

import org.apache.james.jdkim.api.BodyHasher;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;
import org.apache.james.jdkim.impl.BodyHasherImpl;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.jdkim.tagvalue.ArcMessageSignatureRecordTemplate;
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

import static org.apache.james.jdkim.DKIMCommon.AAR_HEADER_LOWER;
import static org.apache.james.jdkim.DKIMCommon.AMS_HEADER;
import static org.apache.james.jdkim.DKIMCommon.AMS_HEADER_LOWER;
import static org.apache.james.jdkim.DKIMCommon.AS_HEADER;
import static org.apache.james.jdkim.DKIMCommon.AS_HEADER_LOWER;
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
        throws  PermFailException, TempFailException
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
        catch (IOException e)
        {
            log.error("IO exception during signing", e);
            throw new TempFailException("Temporary error in processing");
        }
        catch(MimeException e)
        {
            throw new PermFailException("MIME parsing exception.", e);
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
                                     DKIMCommon.AMS_HEADER);

            byte[] signatureHash = signature.sign();
            signatureRecord.setSignature(signatureHash);
            return DKIMCommon.AMS_HEADER + ":" + signatureRecord;
        }
        catch (InvalidKeyException e) {
            throw new PermFailException("Invalid key.", signatureRecord, e);
        } catch (NoSuchAlgorithmException e) {
            throw new PermFailException("Unknown algorithm.", signatureRecord,
                                        e);
        } catch (SignatureException e) {
            throw new PermFailException("Signing error.", signatureRecord,
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
                if (instanceHeaders.containsKey(AAR_HEADER_LOWER)) {
                    String fv = AAR_HEADER_LOWER + ":" + instanceHeaders.get(AAR_HEADER_LOWER);
                    updateSignature(signature, true, AAR_HEADER_LOWER,
                                    fv);
                    signature.update("\r\n".getBytes());
                }

                if (instanceHeaders.containsKey(AMS_HEADER_LOWER)) {

                    String fv = AMS_HEADER_LOWER + ":" + instanceHeaders.get(AMS_HEADER_LOWER);
                    updateSignature(signature, true, AMS_HEADER_LOWER,
                                    fv);
                    signature.update("\r\n".getBytes());
                }

                // Include ARC-Seal for previous instances, but not the current one being verified
                if (instanceHeaders.containsKey(AS_HEADER_LOWER)) {
                    String fv = AS_HEADER_LOWER+ ":" + instanceHeaders.get(AS_HEADER_LOWER);
                    updateSignature(signature, true, AS_HEADER_LOWER,
                                    fv);
                    signature.update("\r\n".getBytes());
                }


            }

            updateSignature(signature, true, AAR_HEADER_LOWER, AAR_HEADER_LOWER + ":" + aar);
            signature.update("\r\n".getBytes());

            updateSignature(signature, true, AMS_HEADER_LOWER, AMS_HEADER_LOWER + ":" + ams);
            signature.update("\r\n".getBytes());

            updateSignature(signature, true, AS_HEADER_LOWER, AAR_HEADER_LOWER + ":" +
                                                              tvl.toUnsignedString());
            tvl.setSignature(signature.sign());

            return DKIMCommon.AS_HEADER + ":" + tvl;
        }
        catch (InvalidKeyException e) {
            throw new PermFailException("Invalid key.", tvl, e);
        } catch (NoSuchAlgorithmException e) {
            throw new PermFailException("Unknown algorithm.", tvl,
                                        e);
        } catch (SignatureException e) {
            throw new PermFailException("Signing error.", tvl,
                                        e);
        }
    }

}
