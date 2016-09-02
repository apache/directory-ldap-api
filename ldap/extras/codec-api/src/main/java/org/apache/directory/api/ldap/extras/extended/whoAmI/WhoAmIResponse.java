/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.ldap.extras.extended.whoAmI;


import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.name.Dn;


/**
 * The RFC 4532 WhoAmI response :
 * 
 * <pre>
 * authzid ::= OCTET STRING OPTIONAL
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface WhoAmIResponse extends ExtendedResponse
{
    /** The OID for the WhoAmI extended operation response. */
    String EXTENSION_OID = WhoAmIRequest.EXTENSION_OID;

    
    /**
     * @return true if the response contains a DN authz (dn:XXX)
     */
    boolean isDnAuthzId();
    
    
    /**
     * @return true if the response contains a userID authz (u:XXX)
     */
    boolean isUserAuthzId();
    

    /**
     * Get the authzid as a byte[]
     * 
     * @return The authzid or null
     */
    byte[] getAuthzId();


    /**
     * Get the authzid as String. We will strip out the 'dn:' or 'u:' part.
     * 
     * @return The authzid or null
     */
    String getAuthzIdString();


    /**
     * Get the UserId
     * 
     * @return The userId or null
     */
    String getUserId();


    /**
     * Get the DN authzid.
     * 
     * @return The DN or null
     */
    Dn getDn();


    /**
     * set the authzid
     * 
     * @param authzId The authzId to set
     */
    void setAuthzId( byte[] authzId );
}
