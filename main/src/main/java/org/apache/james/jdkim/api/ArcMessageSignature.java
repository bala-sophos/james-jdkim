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
 * ARC-Message-Signature record interface.
 * Similar to DKIM-Signature but includes instance number (i=) and must include
 * ARC-Authentication-Results in the signed headers.
 */
public interface ArcMessageSignature extends SignatureRecord {
    
    /**
     * Get the instance number (i= tag) for this ARC signature.
     * @return the instance number
     */
    int getInstance();
    
    /**
     * Set the instance number (i= tag) for this ARC signature.
     * @param instance the instance number
     */
    void setInstance(int instance);
    
    /**
     * ARC-Message-Signature must include ARC-Authentication-Results in the signed headers.
     * This method ensures ARC-Authentication-Results is included.
     * @return list of headers including ARC-Authentication-Results
     */
    List<CharSequence> getHeadersWithAAR();
}

