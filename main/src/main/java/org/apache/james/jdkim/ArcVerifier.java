
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
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.PublicKeyRecord;
import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;
import org.apache.james.jdkim.impl.BodyHasherImpl;
import org.apache.james.jdkim.tagvalue.ArcMessageSignatureRecordImpl;
import org.apache.james.jdkim.tagvalue.ArcSealSignatureRecordImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.apache.james.jdkim.DKIMCommon.signatureCheck;
import static org.apache.james.jdkim.DKIMCommon.updateSignature;

public class ArcVerifier extends DKIMVerifier
{
    Logger  log = LoggerFactory.getLogger(ArcVerifier.class);
    private static final Pattern                  INSTANCE_PATTERN = Pattern.compile("i=(\\d+)");
    /**
     * Constructs an ARC Chain Validator
     *
     * @param publicKeyRecordRetriever DNS retriever for public keys
     */
    public ArcVerifier(PublicKeyRecordRetriever publicKeyRecordRetriever)
    {
        super(publicKeyRecordRetriever);
    }


    /**
     * Validates an ARC chain in a message
     *
     * @param headers Email message headers
     * @return ARC validation result
     *
     */
    public ArcValidationResult validate(Headers headers,
                                        Map<Integer, Map<String, String>> instances,
                                        BodyHasherImpl bodyHasher)
    {
        try
        {

            // No ARC headers found
            if (instances.isEmpty()) {
                return ArcValidationResult.none();
            }

            // Find the highest instance number
            int maxInstance = Collections.max(instances.keySet());

            // Check if the chain is complete
            for (int i = 1; i <= maxInstance; i++) {
                if (!instances.containsKey(i)) {
                    return ArcValidationResult.fail("Incomplete ARC chain. Missing instance " + i);
                }
            }

            log.debug("Complete ARC chain with {} instances found.", maxInstance);

            // Start with PASS for an empty set or initial validation
            String chainValidationStatus = "pass";


            // Check if the chain is complete
            for (int i = 1; i <= maxInstance; i++) {
                Map<String, String> instanceHeaders = instances.get(i);

                // Check required headers
                if (!instanceHeaders.containsKey("arc-seal") ||
                    !instanceHeaders.containsKey("arc-message-signature") ||
                    !instanceHeaders.containsKey("arc-authentication-results")) {
                    return ArcValidationResult.fail("Missing required ARC headers in instance " + i);
                }


                log.debug("ARC instance: {}", i) ;
                log.debug("ARC-Authentication-Results: {}", instances.get(i).get("arc-authentication-results")) ;
                log.debug("ARC-Message-Signature: {}", instances.get(i).get("arc-message-signature")) ;
                log.debug("ARC-Seal: {}", instances.get(i).get("arc-seal")) ;

                // Get the CV value from the current ARC-Seal
                String arcSeal = instanceHeaders.get("arc-seal");

                // Parse the ARC-Seal header
                ArcSealSignatureRecordImpl tvl = new ArcSealSignatureRecordImpl(arcSeal);
                String cv = tvl.getCv().toString();

                // For the oldest/first instance, cv must be "none"
                if (i == 1 && !"none".equalsIgnoreCase(cv)) {
                    return ArcValidationResult.fail("First ARC instance must have cv=none");
                }

                // For intermediate instances, cv must match the previous validation result
                if (i > 1 && !cv.equalsIgnoreCase(chainValidationStatus)) {
                    return ArcValidationResult.fail("Chain validation status mismatch at instance " + i);
                }

                // Verify ARC-Seal for this instance
                boolean sealValid = verifyArcSeal(instances.get(i).get("arc-seal"), instances);
                if (!sealValid) {
                    return ArcValidationResult.fail("Invalid ARC-Seal for instance " + i);
                }

                // Update chain validation status based on current instance results
                // For oldest instance in chain, trust its assessment
                // For newer instances, if anything fails, whole chain fails
                if (i > 1 && (!"pass".equalsIgnoreCase(chainValidationStatus) || !sealValid)) {
                    chainValidationStatus = "fail";
                }
            }

            String messageSignature = "arc-message-signature" + ":"  +
                                      instances.get(maxInstance).get("arc-message-signature");
            //messageSignature = messageSignature.replace("i=4;" , "v=1;");
            log.debug("Signature to verify:" + messageSignature);


            // Verify ARC-Message-Signature for this instance
            //byte[] bodyDigest = getBodyDigest(message, instances.get(maxInstance).get("arc-message-signature"));
            boolean amsValid = verifyArcMessageSignature(headers, bodyHasher.getDigest(), instances.get(maxInstance).get("arc-message-signature"));
            //boolean amsValid = verifyArcMessageSignature(message, messageSignature);
            if (!amsValid) {
                return ArcValidationResult.fail("Invalid ARC-Message-Signature for instance " + maxInstance);
            }

            // If we got here and the status is still "pass", the chain is valid
            return "pass".equalsIgnoreCase(chainValidationStatus) ?
                   ArcValidationResult.pass(instances) :
                   ArcValidationResult.fail("ARC chain validation failed");
        }
        catch(Exception e)
        {
            log.error("Exception during ARC validation", e);
            return ArcValidationResult.fail("Exception during ARC validation: " + e.getMessage());
        }
    }

    /**
     * Groups ARC headers by instance number
     */
    public Map<Integer, Map<String, String>> groupArcHeadersByInstance(List<String> headers) {
        Map<String, List<String>> arcHeaders = extractArcHeaders(headers);
        Map<Integer, Map<String, String>> instances = new LinkedHashMap<>();

        // Process each header type
        for (Map.Entry<String, List<String>> entry : arcHeaders.entrySet()) {
            String headerName = entry.getKey();
            List<String> headerValues = entry.getValue();

            for (String value : headerValues) {
                Matcher m = INSTANCE_PATTERN.matcher(value);
                if (m.find()) {
                    int instance = Integer.parseInt(m.group(1));
                    instances.computeIfAbsent(instance, k -> new HashMap<>()).put(headerName, value);
                }
            }
        }

        return instances;
    }
    /**
     * Extracts all ARC headers from a message
     */
    private Map<String, List<String>> extractArcHeaders(List<String> headers) {
        Map<String, List<String>> arcHeaders = new HashMap<>();

        for (String header : headers) {
            String lcHeader = header.toLowerCase();
            if (lcHeader.startsWith("arc-authentication-results:")) {
                addHeader(arcHeaders, "arc-authentication-results", header.substring(27).trim());
            } else if (lcHeader.startsWith("arc-message-signature:")) {
                addHeader(arcHeaders, "arc-message-signature", header.substring(22).trim());
            } else if (lcHeader.startsWith("arc-seal:")) {
                addHeader(arcHeaders, "arc-seal", header.substring(9).trim());
            }
        }

        return arcHeaders;
    }

    /**
     * Helper method to add a header to the headers map
     */
    private void addHeader(Map<String, List<String>> headers, String name, String value) {
        headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
    }



    /**
     * Verifies an ARC-Seal signature
     */
    public boolean verifyArcSeal(String arcSeal,
                                  Map<Integer, Map<String, String>> instances)
        throws Exception {


        // Parse the ARC-Seal header
        ArcSealSignatureRecordImpl tvl = new ArcSealSignatureRecordImpl(arcSeal);
        int currentInstance = Integer.parseInt(tvl.getInstance().toString());
        log.debug("Verifying ARC-Seal for instance {}: {}", currentInstance, arcSeal);
        // Extract essential fields
        String domain = tvl.getDToken().toString();
        String selector = tvl.getSelector().toString();
        int instanceNum = Integer.parseInt(tvl.getInstance().toString());

        // Verify the instance number matches
        if (instanceNum != currentInstance) {
            log.info("Instance number mismatch: expected {}, found {}", currentInstance, instanceNum);
            return false;
        }

        // Retrieve the public key
        PublicKeyRecord publicKeyRecord = publicRecordLookup(tvl);

        if (publicKeyRecord == null) {
            log.info("Public key not found for selector {} and domain {}", selector, domain);
            return false;
        }

        // Parse the public key record
        PublicKey publicKey;

        try {
            publicKey = publicKeyRecord.getPublicKey();
        } catch (IllegalStateException e) {
            log.error("Invalid public key record: {}", e.getMessage());
            throw new PermFailException("Invalid Public Key: " + e.getMessage(), tvl, e);
        }

        Signature signature = Signature.getInstance(tvl.getHashMethod()
                                                        .toString().toUpperCase()
                                                    + "with" + tvl.getHashKeyType().toString().toUpperCase());


        signature.initVerify(publicKey);



        for (int i = 1; i <= currentInstance; i++)
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
            if (i != currentInstance && instanceHeaders.containsKey("arc-seal")) {
                String fv = "arc-seal"+ ":" + instanceHeaders.get("arc-seal");
                updateSignature(signature, true, "arc-seal",
                                fv);
                signature.update("\r\n".getBytes());
            }
        }

        // Add the current ARC-Seal header without the signature (b=) value
        //String currentArcSeal = instances.get(currentInstance).get("arc-seal");
        String modifiedSeal = tvl.toUnsignedString();//currentArcSeal.replaceAll("b=[^;]+", "b=");
        log.debug("Modified ARC-Seal for verification: {}", modifiedSeal);
        updateSignature(signature, true, "arc-seal", "arc-seal" + ":" + modifiedSeal);

        if (!signature.verify(tvl.getSignature()))
        {
            log.info("ARC-Seal signature verification failed for instance {}", currentInstance);
            return false;
        }

        log.debug("ARC-Seal signature verified for instance {}", currentInstance);
        return true;

    }

    private boolean verifyArcMessageSignature(Headers headers,
                                              byte[] computedBodyHash,
                                              String arcMessageSignatureToVerify)
        throws PermFailException, TempFailException
    {

        SignatureRecord signatureRecord =
            new ArcMessageSignatureRecordImpl(arcMessageSignatureToVerify);

        byte[] expectedBodyHash = signatureRecord.getBodyHash();

        if (!Arrays.equals(expectedBodyHash, computedBodyHash)) {
            System.out.println("Expected body hash: " + new String(Base64.getEncoder().encode(expectedBodyHash)));
            System.out.println("Computed body hash: " + new String(Base64.getEncoder().encode(computedBodyHash)));
            throw new PermFailException(
                "Computed bodyhash is different from the expected one", signatureRecord);
        }
        // Specification say we MAY refuse to verify the signature.
        if (signatureRecord.getSignatureTimestamp() != null) {
            Instant signedTime = Instant.ofEpochSecond(signatureRecord.getSignatureTimestamp());
            Instant now = Instant.now();
            if (signedTime.isAfter(now.plus(options.getClockDriftTolerance()))) {
                // RFC 6376, Section 3.5 page 25, about clock drift:
                // Receivers MAY add a 'fudge factor' to allow for such possible drift.
                Duration diff = Duration.between(now, signedTime);
                String diffText;
                if (diff.toMillis() >= 86400000) {
                    diffText = diff.toDays() + " day(s)";
                } else if (diff.toMillis() >= 3600000) {
                    diffText = diff.toHours() + " hour(s)";
                } else if (diff.toMillis() >= 60000) {
                    diffText = diff.toMinutes() + " minute(s)";
                } else {
                    diffText = (diff.toMillis() / 1000) + " second(s)";
                }
                throw new PermFailException("Signature date is more than "
                                            + diffText + " in the future.", signatureRecord);
            }
        }

        // TODO here we could check more parameters for
        // validation before running a network operation like the
        // dns lookup.
        // e.g: the canonicalization method could be checked now.
        PublicKeyRecord publicKeyRecord = publicRecordLookup(signatureRecord);

        List<CharSequence> signedHeadersList = signatureRecord.getHeaders();

        try {
            byte[] decoded = signatureRecord.getSignature();
            signatureVerify(headers, signatureRecord, decoded,
                            publicKeyRecord, signedHeadersList);
        } catch (IllegalArgumentException e) {
            throw new PermFailException("Invalid signature record: " + e.getMessage(), signatureRecord, e);
        }

        return true;
    }

    private void signatureVerify(Headers h, SignatureRecord sign,
                                 byte[] decoded, PublicKeyRecord key, List<CharSequence> headers)
        throws PermFailException {
        try {
            Signature signature = Signature.getInstance(sign.getHashMethod()
                                                            .toString().toUpperCase()
                                                        + "with" + sign.getHashKeyType().toString().toUpperCase());
            PublicKey publicKey;
            try {
                publicKey = key.getPublicKey();
            } catch (IllegalStateException e) {
                throw new PermFailException("Invalid Public Key: " + e.getMessage(), sign, e);
            }
            signature.initVerify(publicKey);

            signatureCheck(h, sign, headers, signature, DKIMCommon.ARC_MESSAGE_SIGNATURE_HEADER);

            if (!signature.verify(decoded))
                throw new PermFailException("Header signature does not verify", sign);
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new PermFailException(e.getMessage(), sign, e);
        }
    }


}
