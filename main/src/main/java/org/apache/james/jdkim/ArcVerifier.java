package org.apache.james.jdkim;

import org.apache.james.jdkim.api.ArcValidationResult;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.PublicKeyRecord;
import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.jdkim.tagvalue.ArcSealSignatureRecordImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.apache.james.jdkim.DKIMCommon.updateSignature;

public class ArcVerifier
{
    Logger  log = LoggerFactory.getLogger(ArcVerifier.class);
    private static final Pattern                  INSTANCE_PATTERN = Pattern.compile("i=(\\d+)");
    private final        PublicKeyRecordRetriever publicKeyRecordRetriever;

    private final        DKIMVerifier dkimVerifier;
    /**
     * Constructs an ARC Chain Validator
     *
     * @param publicKeyRecordRetriever DNS retriever for public keys
     */
    public ArcVerifier(PublicKeyRecordRetriever publicKeyRecordRetriever)
    {
        this.publicKeyRecordRetriever = publicKeyRecordRetriever;
        this.dkimVerifier = new DKIMVerifier();
    }


    /**
     * Validates an ARC chain in a message
     *
     * @param message The email message to validate
     * @return ARC validation result
     *
     */
    public ArcValidationResult validate(Message message)
    {
        try
        {
            Map<String, List<String>> arcHeaders = extractArcHeaders(message);

            // Group ARC headers by instance
            Map<Integer, Map<String, String>> instances = groupByInstance(arcHeaders);


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
                boolean sealValid = verifyArcSeal(message, instances.get(i).get("arc-seal"), instances, i);
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
            log.info("Signature to verify:" + messageSignature);


            // Verify ARC-Message-Signature for this instance
            boolean amsValid = verifyArcMessageSignature(message, messageSignature);
            if (!amsValid) {
                return ArcValidationResult.fail("Invalid ARC-Message-Signature for instance " + maxInstance);
            }

            // If we got here and the status is still "pass", the chain is valid
            return "pass".equalsIgnoreCase(chainValidationStatus) ?
                   ArcValidationResult.pass(maxInstance) :
                   ArcValidationResult.fail("ARC chain validation failed");
        }
        catch(Exception e)
        {
            log.error("Exception during ARC validation", e);
            return ArcValidationResult.fail("Exception during ARC validation: " + e.getMessage());
        }
    }

    /**
     * Verifies an ARC-Message-Signature (leverages DKIM verification)
     */
    public boolean verifyArcMessageSignature(Message message, String arcMessageSignature)
        throws Exception {
        // ARC-Message-Signature is structurally identical to a DKIM signature
        // We can use the DKIM verifier with some adaptations

        try {
            // Use the DKIM verifier to validate the signature
            dkimVerifier.verify(new Headers()
            {
                @Override
                public List<String> getFields()
                {
                    return message.getFields();
                }

                @Override
                public List<String> getFields(String name)
                {
                    if (name.equalsIgnoreCase("ARC-Message-Signature"))
                    {
                        // Return only the ARC-Message-Signature that we want to verify.
                        return Collections.singletonList(arcMessageSignature);
                    }
                    // For other headers, return actual message headers
                    return message.getFields(name);
                }
            }, message.getBodyInputStream(), "ARC-Message-Signature");
            return true;
        } catch (IOException | FailException e) {
            log.error("ARC-Message-Signature verification error: {}", e.getMessage(), e);
            // Signature verification failed
            return false;
        }
    }
    /**
     * Extracts all ARC headers from a message
     */
    private Map<String, List<String>> extractArcHeaders(Message message) {
        Map<String, List<String>> arcHeaders = new HashMap<>();

        for (String header : message.getFields()) {
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
     * Groups ARC headers by instance number
     */
    private Map<Integer, Map<String, String>> groupByInstance(Map<String, List<String>> arcHeaders) {
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
     * Verifies an ARC-Seal signature
     */
    private boolean verifyArcSeal(Message message, String arcSeal,
                                  Map<Integer, Map<String, String>> instances, int currentInstance)
        throws Exception {

        log.debug("Verifying ARC-Seal for instance {}: {}", currentInstance, arcSeal);
        // Parse the ARC-Seal header
        ArcSealSignatureRecordImpl tvl = new ArcSealSignatureRecordImpl(arcSeal);

        // Extract essential fields
        String domain = tvl.getDToken().toString();
        String selector = tvl.getSelector().toString();
        int instanceNum = Integer.parseInt(tvl.getInstance().toString());

        // Verify the instance number matches
        if (instanceNum != currentInstance) {
            log.debug("Instance number mismatch: expected {}, found {}", currentInstance, instanceNum);
            return false;
        }

        // Retrieve the public key
        PublicKeyRecord publicKeyRecord = dkimVerifier.publicRecordLookup(tvl);

        if (publicKeyRecord == null) {
            log.debug("Public key not found for selector {} and domain {}", selector, domain);
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
        String currentArcSeal = instances.get(currentInstance).get("arc-seal");
        String modifiedSeal = currentArcSeal.replaceAll("b=[^;]+", "b=");
        log.debug("Modified ARC-Seal for verification: {}", modifiedSeal);
        updateSignature(signature, true, "arc-seal", "arc-seal" + ":" + modifiedSeal);

        if (!signature.verify(tvl.getSignature()))
        {
            log.debug("ARC-Seal signature verification failed for instance {}", currentInstance);
            return false;
        }

        log.debug("ARC-Seal signature verified for instance {}", currentInstance);
        return true;

    }
}