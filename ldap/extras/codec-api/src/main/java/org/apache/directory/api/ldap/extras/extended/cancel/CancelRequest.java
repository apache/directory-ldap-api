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
package org.apache.directory.api.ldap.extras.extended.cancel;


import org.apache.directory.api.ldap.model.message.ExtendedRequest;


/**
 * The CancelRequest interface, as described in RFC 3909 :
 * 
 * <pre>
 * cancelRequestValue ::= SEQUENCE {
 *        cancelID        MessageID
 *                        -- MessageID is as defined in [RFC2251]
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface CancelRequest extends ExtendedRequest
{
    /** The OID for the Cancel extended operation request. */
    String EXTENSION_OID = "1.3.6.1.1.8";


    /**
     * Get the cancel ID
     * 
     *  @return The id of the Message to cancel.
     */
    int getCancelId();


    /**
     * Sets the message to cancel by id.
     *
     * @param cancelId The id of the message to cancel.
     */
    void setCancelId( int cancelId );
}
