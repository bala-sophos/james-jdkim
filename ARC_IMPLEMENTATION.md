# ARC (Authenticated Received Chain) Implementation

This document describes the ARC implementation added to the james-jdkim library.

## Overview

ARC (Authenticated Received Chain) is an email authentication system that allows intermediate mail servers to sign an email's original authentication results, preserving the authentication chain through intermediaries. This implementation extends the james-jdkim library to support both ARC verification and sealing.

## Key Components

### 1. ARC Record Interfaces

- **`ArcMessageSignature`**: Interface for ARC-Message-Signature records (similar to DKIM-Signature but with instance number)
- **`ArcSeal`**: Interface for ARC-Seal records (signs all ARC headers)
- **`ArcChainResult`**: Result of ARC chain verification
- **`ArcInstanceResult`**: Result of verifying a single ARC instance

### 2. ARC Verifier (`ARCVerifier`)

The `ARCVerifier` class verifies ARC chains in email messages:

```java
import org.apache.james.jdkim.ARCVerifier;
import org.apache.james.jdkim.api.ArcChainResult;
import java.io.InputStream;

// Create verifier with default DNS-based public key retriever
ARCVerifier verifier = new ARCVerifier();

// Or with custom public key retriever
ARCVerifier verifier = new ARCVerifier(customPublicKeyRecordRetriever);

// Verify ARC chain
InputStream messageStream = ...;
ArcChainResult result = verifier.verify(messageStream);

// Check result
if (result.isPass()) {
    System.out.println("ARC chain is valid");
} else if (result.isFail()) {
    System.out.println("ARC chain validation failed: " + result.getErrorMessage());
} else {
    System.out.println("No ARC headers present");
}
```

### 3. ARC Sealer (`ARCSealer`)

The `ARCSealer` class generates ARC seals for email messages:

```java
import org.apache.james.jdkim.ARCSealer;
import org.apache.james.jdkim.api.ArcChainResult;
import java.io.InputStream;
import java.security.PrivateKey;

// Create sealer
PrivateKey privateKey = ...;
String domain = "example.com";
String selector = "selector1";
String signatureTemplate = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; h=from:to:subject:arc-authentication-results; s=selector1;";

ARCSealer sealer = new ARCSealer(privateKey, domain, selector, signatureTemplate);

// Seal message
InputStream messageStream = ...;
String authenticationResults = "i=1; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass";
ArcChainResult.ChainStatus chainValidation = ArcChainResult.ChainStatus.PASS; // or NONE, FAIL

ARCSealer.ArcSealResult sealResult = sealer.seal(messageStream, authenticationResults, chainValidation);

// Get ARC headers to add to message
List<String> arcHeaders = sealResult.getArcHeaders();
// arcHeaders contains:
// - ARC-Authentication-Results
// - ARC-Message-Signature
// - ARC-Seal
```

## Usage Example

### Complete Example: Receiving, Verifying, Modifying, and Sealing

```java
import org.apache.james.jdkim.ARCVerifier;
import org.apache.james.jdkim.ARCSealer;
import org.apache.james.jdkim.api.ArcChainResult;
import java.io.InputStream;
import java.security.PrivateKey;

// 1. Receive message and verify ARC chain
ARCVerifier verifier = new ARCVerifier();
InputStream receivedMessage = ...;
ArcChainResult arcResult = verifier.verify(receivedMessage);

// 2. Determine chain validation status
ArcChainResult.ChainStatus chainStatus;
if (arcResult.isPass()) {
    chainStatus = ArcChainResult.ChainStatus.PASS;
} else if (arcResult.isFail()) {
    chainStatus = ArcChainResult.ChainStatus.FAIL;
} else {
    chainStatus = ArcChainResult.ChainStatus.NONE;
}

// 3. Perform authentication checks (SPF, DKIM, DMARC)
String authenticationResults = buildAuthenticationResults(/* your auth results */);

// 4. Modify message as needed
// ... modify message ...

// 5. Seal message with new ARC instance
PrivateKey privateKey = ...;
String domain = "yourdomain.com";
String selector = "selector1";
String signatureTemplate = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=yourdomain.com; h=from:to:subject:arc-authentication-results; s=selector1;";

ARCSealer sealer = new ARCSealer(privateKey, domain, selector, signatureTemplate);
InputStream modifiedMessage = ...;
ARCSealer.ArcSealResult sealResult = sealer.seal(modifiedMessage, authenticationResults, chainStatus);

// 6. Add ARC headers to message before delivery
List<String> arcHeaders = sealResult.getArcHeaders();
// Add these headers to your message in order:
// - sealResult.getArcAuthenticationResults()
// - sealResult.getArcMessageSignature()
// - sealResult.getArcSeal()
```

## Differences from DKIM

1. **Instance Numbers**: ARC uses instance numbers (i=) to track the chain
2. **ARC-Authentication-Results**: ARC-Message-Signature must include ARC-Authentication-Results in signed headers
3. **ARC-Seal**: Signs all ARC headers (AAR, AMS, and previous AS headers)
4. **Chain Validation**: ARC-Seal includes chain validation status (cv=) from previous verification

## Implementation Details

### ARC-Message-Signature

- Similar to DKIM-Signature but includes instance number (i=)
- Must include ARC-Authentication-Results in signed headers
- Uses same signing algorithms as DKIM (rsa-sha256, etc.)

### ARC-Seal

- Signs all ARC headers for the current instance
- Includes chain validation status (cv=none|pass|fail)
- Always uses relaxed canonicalization

### ARC Chain Verification

- Verifies each instance in order (1, 2, 3, ...)
- Validates ARC-Message-Signature (similar to DKIM)
- Validates ARC-Seal (signs all ARC headers)
- Returns detailed results for each instance

## Notes

- ARC uses the same public key lookup mechanism as DKIM (DNS TXT records)
- ARC-Seal always uses relaxed canonicalization
- ARC-Message-Signature can use simple or relaxed canonicalization (as specified in signature template)
- The implementation follows RFC 8617 specifications

