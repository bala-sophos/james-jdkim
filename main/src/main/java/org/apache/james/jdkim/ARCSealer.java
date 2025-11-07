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

import static org.apache.james.jdkim.DKIMCommon.arcMessageSignatureCheck;
import static org.apache.james.jdkim.DKIMCommon.arcSealCheck;

import org.apache.james.jdkim.api.ArcChainResult;
import org.apache.james.jdkim.api.ArcMessageSignature;
import org.apache.james.jdkim.api.ArcSeal;
import org.apache.james.jdkim.api.BodyHasher;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.impl.BodyHasherImpl;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.jdkim.tagvalue.ArcMessageSignatureTemplate;
import org.apache.james.jdkim.tagvalue.ArcSealImpl;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;

/**
 * ARC (Authenticated Received Chain) Sealer.
 * Generates ARC seals for email messages according to RFC 8617.
 */
public class ARCSealer {
    
    private final PrivateKey privateKey;
    private final String domain;
    private final String selector;
    private final String signatureTemplate;
    
    /**
     * Creates an ARCSealer with the specified parameters.
     * 
     * @param privateKey the private key for signing
     * @param domain the domain (d= tag)
     * @param selector the selector (s= tag)
     * @param signatureTemplate template for ARC-Message-Signature (e.g., "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; h=from:to:subject:arc-authentication-results; s=selector1;")
     */
    public ARCSealer(PrivateKey privateKey, String domain, String selector, String signatureTemplate) {
        this.privateKey = privateKey;
        this.domain = domain;
        this.selector = selector;
        this.signatureTemplate = signatureTemplate;
    }
    
    /**
     * Seals a message with ARC headers.
     * This method:
     * 1. Verifies existing ARC chain (if present)
     * 2. Determines the next instance number
     * 3. Creates ARC-Authentication-Results header
     * 4. Creates ARC-Message-Signature
     * 5. Creates ARC-Seal
     * 
     * @param is input stream of the message
     * @param authenticationResults the authentication results string (for ARC-Authentication-Results)
     * @param chainValidation the chain validation status from previous ARC verification (none, pass, fail)
     * @return ArcSealResult containing the ARC headers to add
     * @throws IOException if error occurs handling data
     * @throws FailException if sealing fails
     */
    public ArcSealResult seal(InputStream is, String authenticationResults, 
                              ArcChainResult.ChainStatus chainValidation) 
            throws IOException, FailException {
        Message message;
        try {
            try {
                message = new Message(is);
            } catch (RuntimeException | IOException e) {
                throw e;
            } catch (Exception e1) {
                throw new PermFailException("MIME parsing exception: " + e1.getMessage(), e1);
            }
            try {
                return seal(message, message.getBodyInputStream(), authenticationResults, chainValidation);
            } finally {
                message.dispose();
            }
        } finally {
            is.close();
        }
    }
    
    /**
     * Seals a message with ARC headers.
     * 
     * @param messageHeaders parsed headers
     * @param bodyInputStream input stream for the body
     * @param authenticationResults the authentication results string
     * @param chainValidation the chain validation status
     * @return ArcSealResult containing the ARC headers to add
     * @throws IOException if error occurs handling data
     * @throws FailException if sealing fails
     */
    public ArcSealResult seal(Headers messageHeaders, InputStream bodyInputStream,
                              String authenticationResults, ArcChainResult.ChainStatus chainValidation)
            throws IOException, FailException {
        
        // Determine next instance number
        int nextInstance = determineNextInstance(messageHeaders);
        
        // Create ARC-Authentication-Results header
        String aarHeader = createArcAuthenticationResults(nextInstance, authenticationResults);
        
        // Create ARC-Message-Signature
        ArcMessageSignature ams = createArcMessageSignature(messageHeaders, bodyInputStream, 
                                                             nextInstance, aarHeader);
        
        // Get existing ARC headers for seal
        List<String> existingAarHeaders = messageHeaders.getFields("ARC-Authentication-Results");
        List<String> existingAmsHeaders = messageHeaders.getFields("ARC-Message-Signature");
        List<String> existingAsHeaders = messageHeaders.getFields("ARC-Seal");
        
        // Create ARC-Seal
        ArcSeal as = createArcSeal(messageHeaders, nextInstance, chainValidation,
                                   existingAarHeaders, existingAmsHeaders, existingAsHeaders,
                                   aarHeader, "ARC-Message-Signature:" + ams.toString());
        
        return new ArcSealResult(aarHeader, "ARC-Message-Signature:" + ams.toString(),
                                "ARC-Seal:" + as.toString());
    }
    
    /**
     * Determines the next instance number based on existing ARC headers.
     */
    private int determineNextInstance(Headers messageHeaders) {
        List<String> arcSeals = messageHeaders.getFields("ARC-Seal");
        if (arcSeals == null || arcSeals.isEmpty()) {
            return 1;
        }
        
        int maxInstance = 0;
        for (String as : arcSeals) {
            try {
                int colonIndex = as.indexOf(':');
                if (colonIndex < 0) continue;
                String value = as.substring(colonIndex + 1).trim();
                int iIndex = value.indexOf("i=");
                if (iIndex < 0) continue;
                int semicolonIndex = value.indexOf(';', iIndex);
                if (semicolonIndex < 0) semicolonIndex = value.length();
                String instanceStr = value.substring(iIndex + 2, semicolonIndex).trim();
                int instance = Integer.parseInt(instanceStr);
                if (instance > maxInstance) {
                    maxInstance = instance;
                }
            } catch (Exception e) {
                // Skip invalid ARC-Seal
            }
        }
        
        return maxInstance + 1;
    }
    
    /**
     * Creates ARC-Authentication-Results header.
     */
    private String createArcAuthenticationResults(int instance, String authenticationResults) {
        return String.format("ARC-Authentication-Results: i=%d; %s", instance, authenticationResults);
    }
    
    /**
     * Creates ARC-Message-Signature (similar to DKIM signature).
     */
    private ArcMessageSignature createArcMessageSignature(Headers messageHeaders, 
                                                          InputStream bodyInputStream,
                                                          int instance, String aarHeader)
            throws IOException, PermFailException {
        
        // Create signature template with instance number
        String templateWithInstance = signatureTemplate + " i=" + instance + ";";
        ArcMessageSignatureTemplate amsTemplate = new ArcMessageSignatureTemplate(templateWithInstance);
        
        // Ensure ARC-Authentication-Results is in signed headers
        List<CharSequence> headers = amsTemplate.getHeadersWithAAR();
        
        // Compute body hash
        BodyHasherImpl bhj = new BodyHasherImpl(amsTemplate);
        DKIMCommon.streamCopy(bodyInputStream, bhj.getOutputStream());
        byte[] bodyHash = bhj.getDigest();
        amsTemplate.setBodyHash(bodyHash);
        
        // Sign headers
        byte[] signatureHash;
        try {
            signatureHash = signatureSign(messageHeaders, amsTemplate, privateKey, headers);
            amsTemplate.setSignature(signatureHash);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new PermFailException("ARC-Message-Signature signing failed: " + e.getMessage(), e);
        }
        
        return amsTemplate.toArcMessageSignature(
            org.apache.james.jdkim.api.SigningAlgorithm.RSA,
            org.apache.james.jdkim.api.HashMethod.SHA256,
            bodyHash, signatureHash);
    }
    
    /**
     * Creates ARC-Seal.
     */
    private ArcSeal createArcSeal(Headers messageHeaders, int instance,
                                  ArcChainResult.ChainStatus chainValidation,
                                  List<String> existingAarHeaders,
                                  List<String> existingAmsHeaders,
                                  List<String> existingAsHeaders,
                                  String newAarHeader, String newAmsHeader)
            throws PermFailException {
        
        // Create ARC-Seal template
        String cvValue = chainValidation == null ? "none" : 
                        chainValidation == ArcChainResult.ChainStatus.PASS ? "pass" : "fail";
        long timestamp = System.currentTimeMillis() / 1000;
        
        String sealTemplate = String.format(
            "v=1; a=rsa-sha256; b=; cv=%s; d=%s; i=%d; s=%s; t=%d",
            cvValue, domain, instance, selector, timestamp);
        
        ArcSealImpl as = new ArcSealImpl(sealTemplate);
        
        // Collect all ARC headers to sign
        List<String> aarHeaders = new ArrayList<>();
        List<String> amsHeaders = new ArrayList<>();
        List<String> asHeaders = new ArrayList<>();
        
        // Add existing ARC headers
        if (existingAarHeaders != null) {
            aarHeaders.addAll(existingAarHeaders);
        }
        if (existingAmsHeaders != null) {
            amsHeaders.addAll(existingAmsHeaders);
        }
        if (existingAsHeaders != null) {
            asHeaders.addAll(existingAsHeaders);
        }
        
        // Add new ARC headers
        aarHeaders.add(newAarHeader);
        amsHeaders.add(newAmsHeader);
        
        // Sign ARC-Seal
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            
            arcSealCheck(messageHeaders, instance, aarHeaders, amsHeaders, asHeaders,
                        as.toUnsignedString(), signature);
            
            byte[] sealSignature = signature.sign();
            as.setSignature(sealSignature);
            
            return as;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new PermFailException("ARC-Seal signing failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Signs headers for ARC-Message-Signature (similar to DKIM).
     */
    private byte[] signatureSign(Headers h, SignatureRecord sign, PrivateKey key,
                                List<CharSequence> headers)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, PermFailException {
        
        Signature signature = Signature.getInstance(
            sign.getHashMethod().toString().toUpperCase() + "with" +
            sign.getHashKeyType().toString().toUpperCase());
        signature.initSign(key);
        
        arcMessageSignatureCheck(h, sign, headers, signature);
        return signature.sign();
    }
    
    /**
     * Result of ARC sealing operation.
     */
    public static class ArcSealResult {
        private final String arcAuthenticationResults;
        private final String arcMessageSignature;
        private final String arcSeal;
        
        public ArcSealResult(String arcAuthenticationResults, String arcMessageSignature, String arcSeal) {
            this.arcAuthenticationResults = arcAuthenticationResults;
            this.arcMessageSignature = arcMessageSignature;
            this.arcSeal = arcSeal;
        }
        
        public String getArcAuthenticationResults() {
            return arcAuthenticationResults;
        }
        
        public String getArcMessageSignature() {
            return arcMessageSignature;
        }
        
        public String getArcSeal() {
            return arcSeal;
        }
        
        /**
         * Returns all ARC headers as a list, in the order they should be added to the message.
         */
        public List<String> getArcHeaders() {
            List<String> headers = new ArrayList<>();
            headers.add(arcAuthenticationResults);
            headers.add(arcMessageSignature);
            headers.add(arcSeal);
            return headers;
        }
    }
}

