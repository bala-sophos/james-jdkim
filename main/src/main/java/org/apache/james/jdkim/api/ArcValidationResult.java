package org.apache.james.jdkim.api;
/**
 * Represents the result of an ARC chain validation
 */
public class ArcValidationResult {

    public enum Status {
        NONE,   // No ARC chain present
        PASS,   // Valid ARC chain
        FAIL    // Invalid ARC chain
    }

    private final Status status;
    private final String reason;
    private final int instanceCount;

    private ArcValidationResult(Status status, String reason, int instanceCount) {
        this.status = status;
        this.reason = reason;
        this.instanceCount = instanceCount;
    }

    /**
     * Creates a PASS result
     * @param instanceCount Number of instances in the chain
     * @return ARC validation result
     */
    public static ArcValidationResult pass(int instanceCount) {
        return new ArcValidationResult(Status.PASS, "ARC chain validation passed", instanceCount);
    }

    /**
     * Creates a FAIL result
     * @param reason Reason for failure
     * @return ARC validation result
     */
    public static ArcValidationResult fail(String reason) {
        return new ArcValidationResult(Status.FAIL, reason, 0);
    }

    /**
     * Creates a NONE result (no ARC chain found)
     * @return ARC validation result
     */
    public static ArcValidationResult none() {
        return new ArcValidationResult(Status.NONE, "No ARC chain found", 0);
    }

    public Status getStatus() {
        return status;
    }

    public String getReason() {
        return reason;
    }

    public int getInstanceCount() {
        return instanceCount;
    }

    public boolean isPassed() {
        return status == Status.PASS;
    }

    @Override
    public String toString() {
        return status + (status != Status.NONE ? ": " + reason : "");
    }
}

