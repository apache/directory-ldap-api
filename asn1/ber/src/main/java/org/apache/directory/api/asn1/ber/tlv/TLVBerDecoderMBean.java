/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.asn1.ber.tlv;


/**
 * A MBean used to get stats on the decoding process.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface TLVBerDecoderMBean
{
    /**
     * Get the actual maximum number of bytes that can be used to encode the
     * Length
     * 
     * @return The maximum bytes of the Length
     */
    int getMaxLengthLength();


    /**
     * Get the actual maximum number of bytes that can be used to encode the Tag
     * 
     * @return The maximum length of the Tag
     */
    int getMaxTagLength();


    /**
     * Tell if indefinite length form could be used for Length
     * 
     * @return <code>true</code> if the Indefinite form is allowed
     */
    boolean isIndefiniteLengthAllowed();
}
