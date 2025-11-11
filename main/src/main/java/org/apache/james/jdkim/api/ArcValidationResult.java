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
package org.apache.james.jdkim.api;

import java.util.HashMap;
import java.util.Map;

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

    private final Map<Integer, Map<String, String>> instances;

    private ArcValidationResult(Status status, String reason, Map<Integer, Map<String, String>> instances) {
        this.status = status;
        this.reason = reason;
        this.instances = instances;
        this.instanceCount = instances.size();
    }



    /**
     * Creates a PASS result
     * @param instances Number of instances in the chain
     * @return ARC validation result
     */
    public static ArcValidationResult pass(Map<Integer, Map<String, String>> instances) {
        return new ArcValidationResult(Status.PASS, "ARC chain validation passed", instances);
    }

    /**
     * Creates a FAIL result
     * @param reason Reason for failure
     * @return ARC validation result
     */
    public static ArcValidationResult fail(String reason) {
        return new ArcValidationResult(Status.FAIL, reason, new HashMap<>());
    }

    /**
     * Creates a NONE result (no ARC chain found)
     * @return ARC validation result
     */
    public static ArcValidationResult none() {
        return new ArcValidationResult(Status.NONE, "No ARC chain found", new HashMap<>());
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

    public Map<Integer, Map<String, String>> getAllInstances() {
        return instances;
    }

    @Override
    public String toString() {
        return status + (status != Status.NONE ? ": " + reason : "");
    }
}

