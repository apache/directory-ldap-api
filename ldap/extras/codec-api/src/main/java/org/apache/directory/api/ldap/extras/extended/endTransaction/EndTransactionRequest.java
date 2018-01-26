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
package org.apache.directory.api.ldap.extras.extended.endTransaction;


import org.apache.directory.api.ldap.model.message.ExtendedRequest;


/**
 * The EndTransactionRequest interface. This is for the RFC 5805 End Transaction Request,
 * which grammar is :
 * <pre>
 * ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
 *              requestName      [0] LDAPOID,
 *              requestValue     [1] OCTET STRING OPTIONAL }
 * </pre>
 * 
 * where 'requestName' is 1.3.6.1.1.21.3 and requestValue is a BER encoded value. The 
 * syntax for this value is :
 * 
 * <pre>
 * txnEndReq ::= SEQUENCE {
 *         commit         BOOLEAN DEFAULT TRUE,
 *         identifier     OCTET STRING }
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface EndTransactionRequest extends ExtendedRequest
{
    /** The OID for the EndTransaction extended operation request. */
    String EXTENSION_OID = "1.3.6.1.1.21.3";
    
    /**
     * @return <tt>true</tt> if the operation should be committed, <tt>false</tt> otherwise
     */
    boolean getCommit();
    
    
    /**
     * Set the Commit flag for this transaction.
     * 
     * @param commit <tt>true</tt> if the transaction should be committed, <tt>false</tt> if
     * it should be rollbacked.
     */
    void setCommit( boolean commit );
    
    
    /**
     * @return The transaction ID 
     */
    byte[] getTransactionId();

    /**
     * Set the transaction ID to commit or rollback
     * 
     * @param transactionId The transaction ID we got from the startTransaction response
     */
    void setTransactionId( byte[] transactionId );
}