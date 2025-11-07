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

/**
 * Result of verifying a single ARC instance.
 */
public class ArcInstanceResult {
    
    private final int instance;
    private final boolean amsValid;
    private final boolean asValid;
    private final String amsErrorMessage;
    private final String asErrorMessage;
    private final ArcMessageSignature ams;
    private final ArcSeal as;
    
    public ArcInstanceResult(int instance, boolean amsValid, boolean asValid,
                            String amsErrorMessage, String asErrorMessage,
                            ArcMessageSignature ams, ArcSeal as) {
        this.instance = instance;
        this.amsValid = amsValid;
        this.asValid = asValid;
        this.amsErrorMessage = amsErrorMessage;
        this.asErrorMessage = asErrorMessage;
        this.ams = ams;
        this.as = as;
    }
    
    public int getInstance() {
        return instance;
    }
    
    public boolean isAmsValid() {
        return amsValid;
    }
    
    public boolean isAsValid() {
        return asValid;
    }
    
    public boolean isValid() {
        return amsValid && asValid;
    }
    
    public String getAmsErrorMessage() {
        return amsErrorMessage;
    }
    
    public String getAsErrorMessage() {
        return asErrorMessage;
    }
    
    public ArcMessageSignature getAms() {
        return ams;
    }
    
    public ArcSeal getAs() {
        return as;
    }
}

