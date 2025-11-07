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

package org.apache.james.jdkim.tagvalue;

import org.apache.james.jdkim.api.ArcSeal;

import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/**
 * Implementation of ARC-Seal.
 * ARC-Seal signs all ARC headers (ARC-Authentication-Results, ARC-Message-Signature,
 * and all previous ARC-Seal headers) for a given instance.
 */
public class ArcSealImpl extends TagValue implements ArcSeal {
    
    public ArcSealImpl(String data) {
        super(data);
        validate();
    }
    
    @Override
    protected void init() {
        mandatoryTags.add("i");
        mandatoryTags.add("a");
        mandatoryTags.add("b");
        mandatoryTags.add("cv");
        mandatoryTags.add("d");
        mandatoryTags.add("s");
        mandatoryTags.add("t");
        
        defaults.put("v", "1");
    }
    
    @Override
    public void validate() throws IllegalStateException {
        super.validate();
        
        // Validate instance number
        if (getValue("i") == null) {
            throw new IllegalStateException("ARC-Seal missing instance number (i=)");
        }
        
        try {
            int instance = Integer.parseInt(getValue("i").toString());
            if (instance < 1) {
                throw new IllegalStateException("ARC-Seal instance number must be >= 1");
            }
        } catch (NumberFormatException e) {
            throw new IllegalStateException("ARC-Seal invalid instance number (i=): " + getValue("i"));
        }
        
        // Validate chain validation status
        String cv = getValue("cv").toString().toLowerCase();
        if (!cv.equals("none") && !cv.equals("pass") && !cv.equals("fail")) {
            throw new IllegalStateException("ARC-Seal invalid chain validation status (cv=): " + cv);
        }
        
        // Validate version
        if (!"1".equals(getValue("v").toString())) {
            throw new IllegalStateException("ARC-Seal invalid version (expected '1'): " + getValue("v"));
        }
    }
    
    @Override
    public int getInstance() {
        return Integer.parseInt(getValue("i").toString());
    }
    
    @Override
    public void setInstance(int instance) {
        setValue("i", String.valueOf(instance));
    }
    
    @Override
    public CharSequence getVersion() {
        return getValue("v");
    }
    
    @Override
    public CharSequence getAlgorithm() {
        return getValue("a");
    }
    
    @Override
    public CharSequence getSelector() {
        return getValue("s");
    }
    
    @Override
    public CharSequence getDomain() {
        return getValue("d");
    }
    
    @Override
    public CharSequence getChainValidation() {
        return getValue("cv");
    }
    
    @Override
    public void setChainValidation(CharSequence cv) {
        setValue("cv", cv.toString());
    }
    
    @Override
    public byte[] getSignature() {
        return decodeBase64TagValue("b");
    }
    
    @Override
    public void setSignature(byte[] signature) {
        String signatureStr = new String(Base64.getEncoder().encode(signature));
        setValue("b", signatureStr);
    }
    
    @Override
    public Long getTimestamp() {
        CharSequence cs = getValue("t");
        if (cs == null) return null;
        return Long.parseLong(cs.toString());
    }
    
    @Override
    public void setTimestamp(Long timestamp) {
        setValue("t", String.valueOf(timestamp));
    }
    
    @Override
    public String toUnsignedString() {
        return toString().replaceFirst("b=[^;]*", "b=");
    }
}

