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

import org.apache.james.jdkim.api.ArcMessageSignature;
import org.apache.james.jdkim.api.HashMethod;
import org.apache.james.jdkim.api.SigningAlgorithm;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/**
 * Template for creating ARC-Message-Signature records.
 */
public class ArcMessageSignatureTemplate extends SignatureRecordTemplate implements ArcMessageSignature {
    
    public ArcMessageSignatureTemplate(String data) {
        super(data);
        validate();
        Set<String> tags = getTags();
        defaults.forEach((key, value) -> {
                    if (!tags.contains(key) && !"l".equals(key)) {
                        setValue(key, value.toString());
                    }
                }
        );
    }
    
    @Override
    protected void init() {
        super.init();
        // ARC-Message-Signature has instance number (i=) as mandatory
        mandatoryTags.add("i");
    }
    
    @Override
    public void validate() throws IllegalStateException {
        super.validate();
        
        // Validate instance number
        if (getValue("i") == null) {
            throw new IllegalStateException("ARC-Message-Signature missing instance number (i=)");
        }
        
        try {
            int instance = Integer.parseInt(getValue("i").toString());
            if (instance < 1) {
                throw new IllegalStateException("ARC-Message-Signature instance number must be >= 1");
            }
        } catch (NumberFormatException e) {
            throw new IllegalStateException("ARC-Message-Signature invalid instance number (i=): " + getValue("i"));
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
    
    public ArcMessageSignatureImpl toArcMessageSignature(SigningAlgorithm algorithm, HashMethod hashMethod, 
                                                         byte[] bodyHash, byte[] signature) {
        setValue("a", algorithm.asTagValue() + "-" + hashMethod.asTagValue());
        
        String bodyHashTagValue = new String(Base64.getEncoder().encode(bodyHash));
        setValue("bh", bodyHashTagValue);
        
        String signatureTagValue = new String(Base64.getEncoder().encode(signature));
        setValue("b", signatureTagValue);
        
        // If a t=; parameter is present in the signature, make sure to
        // fill it with the current timestamp
        if (getValue("t") != null && getValue("t").toString().trim().isEmpty()) {
            setValue("t", "" + (System.currentTimeMillis() / 1000));
        }
        
        return new ArcMessageSignatureImpl(this.toString());
    }
    
    @Override
    public List<CharSequence> getHeadersWithAAR() {
        List<CharSequence> headers = getHeaders();
        // Ensure ARC-Authentication-Results is included
        boolean hasAAR = false;
        for (CharSequence header : headers) {
            if ("arc-authentication-results".equalsIgnoreCase(header.toString())) {
                hasAAR = true;
                break;
            }
        }
        if (!hasAAR) {
            List<CharSequence> newHeaders = new ArrayList<>(headers);
            newHeaders.add(0, "ARC-Authentication-Results");
            return newHeaders;
        }
        return headers;
    }
    
    @Override
    public String toUnsignedString() {
        return toString().replaceFirst("b=[^;]*", "b=");
    }
}

