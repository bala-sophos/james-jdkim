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

import java.util.List;

/**
 * Result of ARC chain verification.
 */
public class ArcChainResult {
    
    public enum ChainStatus {
        NONE,      // No ARC headers present
        PASS,      // Chain is valid
        FAIL       // Chain validation failed
    }
    
    private final ChainStatus status;
    private final int instanceCount;
    private final List<ArcInstanceResult> instanceResults;
    private final String errorMessage;
    
    public ArcChainResult(ChainStatus status, int instanceCount, 
                         List<ArcInstanceResult> instanceResults, String errorMessage) {
        this.status = status;
        this.instanceCount = instanceCount;
        this.instanceResults = instanceResults;
        this.errorMessage = errorMessage;
    }
    
    public ChainStatus getStatus() {
        return status;
    }
    
    public int getInstanceCount() {
        return instanceCount;
    }
    
    public List<ArcInstanceResult> getInstanceResults() {
        return instanceResults;
    }
    
    public String getErrorMessage() {
        return errorMessage;
    }
    
    public boolean isPass() {
        return status == ChainStatus.PASS;
    }
    
    public boolean isFail() {
        return status == ChainStatus.FAIL;
    }
    
    public boolean isNone() {
        return status == ChainStatus.NONE;
    }
}

