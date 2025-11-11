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

import static org.apache.james.jdkim.parser.DKIMQuotedPrintable.dkimQuotedPrintableDecode;

public class ArcSealSignatureRecordTemplate extends SignatureRecordTemplate
{
    public ArcSealSignatureRecordTemplate(String data)
    {
        super(data);
    }


    @Override
    protected void init() {

        // "instance-tag" is mandatory in the ARC-Seal ABNF definition
        mandatoryTags.add("i");
        
        // "selector-tag" in the ARC-Seal ABNF definition
        mandatoryTags.add("s");
       
        // "domain-tag" in the ARC-Seal ABNF definition
        mandatoryTags.add("d");

        // "signature-tag" in the ARC-Seal ABNF definition
        mandatoryTags.add("b");
        
        // "seal-cv-tag" in the ARC-Seal ABNF definition
        mandatoryTags.add("cv");

        // "algorithm-tag" in the ARC-Seal ABNF definition
        mandatoryTags.add("a");


    }

    @Override
    public void validate() throws IllegalStateException {
        // check mandatory fields
        for (String tag : mandatoryTags) {
            if (getValue(tag) == null)
                throw new IllegalStateException("Missing mandatory tag: " + tag);
        }

        if (containsTag("h"))
        {
            throw new IllegalStateException("Invalid ARC-Seal: contains header tag");
        }
    }

    public CharSequence getInstance()
    {
        return getValue("i");
    }


    public CharSequence getCv()
    {
        return getValue("cv");
    }

    @Override
    public CharSequence getHashAlgo()
    {
        return super.getHashAlgo();
    }

    @Override
    public CharSequence getDToken()
    {
        return super.getDToken();
    }

    @Override
    public CharSequence getSelector()
    {
        return super.getSelector();
    }

    @Override
    public byte[] getSignature()
    {
        return super.getSignature();
    }

    @Override
    public CharSequence getRawSignature()
    {
        return super.getRawSignature();
    }

    @Override
    public Long getSignatureTimestamp()
    {
        return super.getSignatureTimestamp();
    }


    @Override
    public CharSequence getIdentity()
    {
        // "identity-tag" is not part of ARC-Seal header deinfiton, but we provide a default value for it as the common signature generation code expects it to be present.
        return dkimQuotedPrintableDecode("@" + getDToken());
    }
}
