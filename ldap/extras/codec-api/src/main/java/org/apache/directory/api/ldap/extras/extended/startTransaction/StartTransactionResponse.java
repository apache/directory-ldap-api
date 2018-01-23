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
package org.apache.directory.api.ldap.extras.extended.startTransaction;


import org.apache.directory.api.ldap.model.message.ExtendedResponse;


/**
 * The interface for Start Transaction Extended Response. It's described in RFC 5805 :
 * 
 * <pre>
 * ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
 *            COMPONENTS OF LDAPResult,
 *            responseName     [10] LDAPOID OPTIONAL,
 *            responseValue    [11] OCTET STRING OPTIONAL }
 * </pre>
 * 
 * where the responseName is not present, and the responseValue contain
 * a transaction identifier when the result is SUCCESS.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface StartTransactionResponse extends ExtendedResponse
{
    /** The OID for the Start Transaction extended operation response. */
    String EXTENSION_OID = StartTransactionRequest.EXTENSION_OID;
    
    
    /**
     * @return The transaction ID if success
     */
    byte[] getTransactionId();
}