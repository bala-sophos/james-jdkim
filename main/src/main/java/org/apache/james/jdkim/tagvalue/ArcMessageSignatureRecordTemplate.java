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

import java.util.Set;

import static org.apache.james.jdkim.parser.DKIMQuotedPrintable.dkimQuotedPrintableDecode;

public class ArcMessageSignatureRecordTemplate extends SignatureRecordTemplate
{

    public ArcMessageSignatureRecordTemplate(String data)
    {
        super(data);
    }

    @Override
    protected void init() {
        super.init();
        /*
        Unlike DKIM-Signature, no version tag ("v") is defined for the AMS header field.  As
      required for undefined tags (in [RFC6376]), if seen, a version tag
      MUST be ignored; 
      */
        mandatoryTags.remove("v");

    }

    @Override
    public CharSequence getIdentity() {
        return dkimQuotedPrintableDecode("@" + getDToken());
    }


    public String toString() {
        return updateStringRepresentation();
    }

    private String updateStringRepresentation() {
        // calculate a new string representation
        StringBuilder res = new StringBuilder();
        Set<String> s = getTags();
        res.append(" ");
        res.append("i");
        res.append("=");
        res.append(getValue("i"));
        res.append(";");
        for (String tag : s) {
            if (tag.equalsIgnoreCase("i"))
                continue;
            res.append(" ");
            res.append(tag);
            res.append("=");
            res.append(getValue(tag));
            res.append(";");
        }
        // TODO add folding
        return res.toString();
    }
}