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
 * ARC-Seal record interface.
 * ARC-Seal signs all ARC headers (ARC-Authentication-Results, ARC-Message-Signature,
 * and all previous ARC-Seal headers) for a given instance.
 */
public interface ArcSeal {
    
    /**
     * Get the instance number (i= tag) for this ARC seal.
     * @return the instance number
     */
    int getInstance();
    
    /**
     * Set the instance number (i= tag) for this ARC seal.
     * @param instance the instance number
     */
    void setInstance(int instance);
    
    /**
     * Get the version (v= tag).
     * @return the version
     */
    CharSequence getVersion();
    
    /**
     * Get the algorithm (a= tag).
     * @return the algorithm
     */
    CharSequence getAlgorithm();
    
    /**
     * Get the selector (s= tag).
     * @return the selector
     */
    CharSequence getSelector();
    
    /**
     * Get the domain (d= tag).
     * @return the domain
     */
    CharSequence getDomain();
    
    /**
     * Get the chain validation status (cv= tag).
     * @return the chain validation status (none, pass, fail)
     */
    CharSequence getChainValidation();
    
    /**
     * Set the chain validation status (cv= tag).
     * @param cv the chain validation status (none, pass, fail)
     */
    void setChainValidation(CharSequence cv);
    
    /**
     * Get the signature (b= tag).
     * @return the signature bytes
     */
    byte[] getSignature();
    
    /**
     * Set the signature (b= tag).
     * @param signature the signature bytes
     */
    void setSignature(byte[] signature);
    
    /**
     * Get the timestamp (t= tag).
     * @return the timestamp
     */
    Long getTimestamp();
    
    /**
     * Set the timestamp (t= tag).
     * @param timestamp the timestamp
     */
    void setTimestamp(Long timestamp);
    
    /**
     * Validate the ARC-Seal record.
     * @throws IllegalStateException if validation fails
     */
    void validate();
    
    /**
     * Get the unsigned string representation (without b= tag).
     * @return the unsigned string
     */
    String toUnsignedString();
    
    /**
     * Get the string representation of this ARC-Seal.
     * @return the string representation
     */
    String toString();
}

