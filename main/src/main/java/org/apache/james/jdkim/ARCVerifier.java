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
import org.apache.james.jdkim.api.ArcInstanceResult;
import org.apache.james.jdkim.api.ArcMessageSignature;
import org.apache.james.jdkim.api.ArcSeal;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.PublicKeyRecord;
import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.api.VerifierOptions;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;
import org.apache.james.jdkim.impl.BodyHasherImpl;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.jdkim.tagvalue.ArcMessageSignatureImpl;
import org.apache.james.jdkim.tagvalue.ArcSealImpl;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * ARC (Authenticated Received Chain) Verifier.
 * Verifies ARC chains in email messages according to RFC 8617.
 */
public class ARCVerifier {
    
    private final VerifierOptions options;
    
    public ARCVerifier() {
        this(new VerifierOptions.Builder().build());
    }
    
    public ARCVerifier(PublicKeyRecordRetriever publicKeyRecordRetriever) {
        this(new VerifierOptions.Builder().withPublicKeyRecordRetriever(publicKeyRecordRetriever).build());
    }
    
    public ARCVerifier(VerifierOptions verifierOptions) {
        this.options = verifierOptions;
    }
    
    protected PublicKeyRecordRetriever getPublicKeyRecordRetriever() {
        return options.getPublicKeyRecordRetriever();
    }
    
    /**
     * Verifies the ARC chain in the message.
     * 
     * @param is input stream of the message
     * @return ArcChainResult with verification results
     * @throws IOException if error occurs handling data
     */
    public ArcChainResult verify(InputStream is) throws IOException {
        Message message;
        try {
            try {
                message = new Message(is);
            } catch (RuntimeException | IOException e) {
                throw e;
            } catch (Exception e1) {
                // This can only be a MimeException but we don't declare to allow usage of
                // ARCVerifier without Mime4J dependency.
                // Wrap in IOException since PermFailException is a checked exception
                throw new IOException("MIME parsing exception: " + e1.getMessage(), e1);
            }
            try {
                return verify(message, message.getBodyInputStream());
            } finally {
                message.dispose();
            }
        } finally {
            is.close();
        }
    }
    
    /**
     * Verifies the ARC chain in the message headers.
     * 
     * @param messageHeaders parsed headers
     * @param bodyInputStream input stream for the body
     * @return ArcChainResult with verification results
     * @throws IOException if error occurs handling data
     */
    public ArcChainResult verify(Headers messageHeaders, InputStream bodyInputStream) throws IOException {
        // Extract all ARC headers
        List<String> arcAuthResults = messageHeaders.getFields("ARC-Authentication-Results");
        List<String> arcMessageSignatures = messageHeaders.getFields("ARC-Message-Signature");
        List<String> arcSeals = messageHeaders.getFields("ARC-Seal");
        
        if (arcAuthResults == null || arcAuthResults.isEmpty() ||
            arcMessageSignatures == null || arcMessageSignatures.isEmpty() ||
            arcSeals == null || arcSeals.isEmpty()) {
            // No ARC headers present
            return new ArcChainResult(ArcChainResult.ChainStatus.NONE, 0, 
                                     Collections.emptyList(), null);
        }
        
        // Parse ARC headers by instance
        Map<Integer, ArcInstance> instances = parseArcInstances(arcAuthResults, 
                                                                 arcMessageSignatures, 
                                                                 arcSeals);
        
        if (instances.isEmpty()) {
            return new ArcChainResult(ArcChainResult.ChainStatus.FAIL, 0,
                                     Collections.emptyList(), "No valid ARC instances found");
        }
        
        // Verify each instance in order
        List<ArcInstanceResult> instanceResults = new ArrayList<>();
        ArcChainResult.ChainStatus chainStatus = ArcChainResult.ChainStatus.PASS;
        String errorMessage = null;
        
        for (int i = 1; i <= instances.size(); i++) {
            ArcInstance instance = instances.get(i);
            if (instance == null) {
                chainStatus = ArcChainResult.ChainStatus.FAIL;
                errorMessage = "Missing ARC instance " + i;
                break;
            }
            
            ArcInstanceResult result = verifyInstance(messageHeaders, bodyInputStream, 
                                                      instance, instances, i);
            instanceResults.add(result);
            
            if (!result.isValid()) {
                chainStatus = ArcChainResult.ChainStatus.FAIL;
                if (errorMessage == null) {
                    errorMessage = "ARC instance " + i + " validation failed";
                }
            }
        }
        
        return new ArcChainResult(chainStatus, instances.size(), instanceResults, errorMessage);
    }
    
    /**
     * Parses ARC headers and groups them by instance number.
     */
    private Map<Integer, ArcInstance> parseArcInstances(List<String> arcAuthResults,
                                                         List<String> arcMessageSignatures,
                                                         List<String> arcSeals) {
        Map<Integer, ArcInstance> instances = new TreeMap<>();
        
        // Parse ARC-Authentication-Results
        for (String aar : arcAuthResults) {
            int instance = extractInstance(aar);
            if (instance > 0) {
                instances.computeIfAbsent(instance, k -> new ArcInstance()).aar = aar;
            }
        }
        
        // Parse ARC-Message-Signature
        for (String ams : arcMessageSignatures) {
            try {
                ArcMessageSignatureImpl amsRecord = new ArcMessageSignatureImpl(
                    ams.substring(ams.indexOf(':') + 1).trim());
                int instance = amsRecord.getInstance();
                instances.computeIfAbsent(instance, k -> new ArcInstance()).ams = ams;
                instances.get(instance).amsRecord = amsRecord;
            } catch (Exception e) {
                // Invalid ARC-Message-Signature, skip
            }
        }
        
        // Parse ARC-Seal
        for (String as : arcSeals) {
            try {
                ArcSealImpl asRecord = new ArcSealImpl(as.substring(as.indexOf(':') + 1).trim());
                int instance = asRecord.getInstance();
                instances.computeIfAbsent(instance, k -> new ArcInstance()).as = as;
                instances.get(instance).asRecord = asRecord;
            } catch (Exception e) {
                // Invalid ARC-Seal, skip
            }
        }
        
        return instances;
    }
    
    /**
     * Extracts instance number from ARC header.
     */
    private int extractInstance(String header) {
        try {
            int colonIndex = header.indexOf(':');
            if (colonIndex < 0) return 0;
            String value = header.substring(colonIndex + 1).trim();
            int iIndex = value.indexOf("i=");
            if (iIndex < 0) return 0;
            int semicolonIndex = value.indexOf(';', iIndex);
            if (semicolonIndex < 0) semicolonIndex = value.length();
            String instanceStr = value.substring(iIndex + 2, semicolonIndex).trim();
            return Integer.parseInt(instanceStr);
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * Verifies a single ARC instance.
     */
    private ArcInstanceResult verifyInstance(Headers messageHeaders, InputStream bodyInputStream,
                                             ArcInstance instance, Map<Integer, ArcInstance> allInstances,
                                             int currentInstance) {
        boolean amsValid = false;
        boolean asValid = false;
        String amsErrorMessage = null;
        String asErrorMessage = null;
        
        // Verify ARC-Message-Signature
        if (instance.amsRecord != null) {
            try {
                amsValid = verifyArcMessageSignature(messageHeaders, bodyInputStream, instance.amsRecord);
            } catch (Exception e) {
                amsErrorMessage = e.getMessage();
            }
        } else {
            amsErrorMessage = "ARC-Message-Signature missing";
        }
        
        // Verify ARC-Seal
        if (instance.asRecord != null) {
            try {
                asValid = verifyArcSeal(messageHeaders, instance, allInstances, currentInstance);
            } catch (Exception e) {
                asErrorMessage = e.getMessage();
            }
        } else {
            asErrorMessage = "ARC-Seal missing";
        }
        
        return new ArcInstanceResult(currentInstance, amsValid, asValid,
                                     amsErrorMessage, asErrorMessage,
                                     instance.amsRecord, instance.asRecord);
    }
    
    /**
     * Verifies ARC-Message-Signature (similar to DKIM verification).
     */
    private boolean verifyArcMessageSignature(Headers messageHeaders, InputStream bodyInputStream,
                                              ArcMessageSignature ams) throws FailException {
        try {
            // Verify body hash
            BodyHasherImpl bhj = new BodyHasherImpl(ams);
            DKIMCommon.streamCopy(bodyInputStream, bhj.getOutputStream());
            byte[] computedHash = bhj.getDigest();
            byte[] expectedBodyHash = ams.getBodyHash();
            
            if (!Arrays.equals(expectedBodyHash, computedHash)) {
                throw new PermFailException("ARC-Message-Signature body hash mismatch", ams);
            }
            
            // Verify header signature
            PublicKeyRecord publicKeyRecord = publicRecordLookup(ams);
            byte[] decoded = ams.getSignature();
            List<CharSequence> signedHeaders = ams.getHeadersWithAAR();
            
            signatureVerify(messageHeaders, ams, decoded, publicKeyRecord, signedHeaders);
            
            return true;
        } catch (PermFailException | TempFailException e) {
            throw e;
        } catch (Exception e) {
            throw new PermFailException("ARC-Message-Signature verification failed: " + e.getMessage(), ams, e);
        }
    }
    
    /**
     * Verifies ARC-Seal.
     */
    private boolean verifyArcSeal(Headers messageHeaders, ArcInstance instance,
                                  Map<Integer, ArcInstance> allInstances, int currentInstance) throws FailException {
        try {
            // Get public key for ARC-Seal
            PublicKeyRecord publicKeyRecord = publicRecordLookupForArcSeal(instance.asRecord);
            
            // Collect all ARC headers to sign
            List<String> aarHeaders = new ArrayList<>();
            List<String> amsHeaders = new ArrayList<>();
            List<String> asHeaders = new ArrayList<>();
            
            // Current instance ARC headers
            if (instance.aar != null) {
                aarHeaders.add(instance.aar);
            }
            if (instance.ams != null) {
                amsHeaders.add(instance.ams);
            }
            
            // Previous ARC-Seal headers
            for (int i = 1; i < currentInstance; i++) {
                ArcInstance prevInstance = allInstances.get(i);
                if (prevInstance != null && prevInstance.as != null) {
                    asHeaders.add(prevInstance.as);
                }
            }
            
            // Verify signature
            Signature signature = Signature.getInstance(
                instance.asRecord.getAlgorithm().toString().toUpperCase());
            PublicKey publicKey = publicKeyRecord.getPublicKey();
            signature.initVerify(publicKey);
            
            arcSealCheck(messageHeaders, currentInstance, aarHeaders, amsHeaders, asHeaders,
                        instance.asRecord.toUnsignedString(), signature);
            
            byte[] decoded = instance.asRecord.getSignature();
            if (!signature.verify(decoded)) {
                throw new PermFailException("ARC-Seal signature does not verify");
            }
            
            return true;
        } catch (PermFailException | TempFailException e) {
            throw e;
        } catch (Exception e) {
            throw new PermFailException("ARC-Seal verification failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Looks up public key record for ARC-Seal.
     */
    private PublicKeyRecord publicRecordLookupForArcSeal(ArcSeal seal) throws TempFailException, PermFailException {
        PublicKeyRecord key = null;
        TempFailException lastTempFailure = null;
        PermFailException lastPermFailure = null;
        
        // ARC-Seal uses DNS/TXT lookup (same as DKIM)
        try {
            List<String> records = getPublicKeyRecordRetriever().getRecords(
                "dns/txt", seal.getSelector().toString(), seal.getDomain().toString());
            PublicKeyRecord tempKey = publicKeySelector(records);
            key = tempKey;
        } catch (TempFailException tf) {
            lastTempFailure = tf;
        } catch (PermFailException pf) {
            lastPermFailure = pf;
        }
        
        if (key == null) {
            if (lastTempFailure != null) {
                throw lastTempFailure;
            } else if (lastPermFailure != null) {
                throw lastPermFailure;
            } else {
                throw new PermFailException("No key for ARC-Seal");
            }
        }
        
        return key;
    }
    
    /**
     * Looks up public key record for ARC signature (similar to DKIM).
     */
    private PublicKeyRecord publicRecordLookup(SignatureRecord sign) throws TempFailException, PermFailException {
        PublicKeyRecord key = null;
        TempFailException lastTempFailure = null;
        PermFailException lastPermFailure = null;
        
        for (CharSequence method : sign.getRecordLookupMethods()) {
            try {
                List<String> records = getPublicKeyRecordRetriever().getRecords(
                    method, sign.getSelector().toString(), sign.getDToken().toString());
                PublicKeyRecord tempKey = publicKeySelector(records);
                key = tempKey;
                break;
            } catch (TempFailException tf) {
                lastTempFailure = tf;
            } catch (PermFailException pf) {
                lastPermFailure = pf;
            }
        }
        
        if (key == null) {
            if (lastTempFailure != null) {
                throw lastTempFailure;
            } else if (lastPermFailure != null) {
                throw lastPermFailure;
            } else {
                throw new PermFailException("No key for signature");
            }
        }
        
        return key;
    }
    
    /**
     * Selects a valid public key from records.
     */
    private PublicKeyRecord publicKeySelector(List<String> records) throws PermFailException {
        if (records == null || records.isEmpty()) {
            throw new PermFailException("No key for signature");
        }
        
        for (String record : records) {
            try {
                PublicKeyRecord pk = new org.apache.james.jdkim.tagvalue.PublicKeyRecordImpl(record);
                pk.validate();
                return pk;
            } catch (IllegalStateException e) {
                // Try next record
            }
        }
        
        throw new PermFailException("Invalid key for signature");
    }
    
    /**
     * Verifies header signature (similar to DKIM).
     */
    private void signatureVerify(Headers h, SignatureRecord sign, byte[] decoded,
                                PublicKeyRecord key, List<CharSequence> headers) throws PermFailException {
        try {
            Signature signature = Signature.getInstance(
                sign.getHashMethod().toString().toUpperCase() + "with" +
                sign.getHashKeyType().toString().toUpperCase());
            PublicKey publicKey = key.getPublicKey();
            signature.initVerify(publicKey);
            
            arcMessageSignatureCheck(h, sign, headers, signature);
            
            if (!signature.verify(decoded)) {
                throw new PermFailException("Header signature does not verify", sign);
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new PermFailException(e.getMessage(), sign, e);
        }
    }
    
    /**
     * Internal class to hold ARC instance data.
     */
    private static class ArcInstance {
        String aar;
        String ams;
        String as;
        ArcMessageSignature amsRecord;
        ArcSeal asRecord;
    }
}

