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


import java.util.List;

import org.apache.directory.api.ldap.model.message.ExtendedResponse;


/**
 * The interface for End Transaction Extended Response. It's described in RFC 5805 :
 * 
 * <pre>
 * ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
 *            COMPONENTS OF LDAPResult,
 *            responseName     [10] LDAPOID OPTIONAL,
 *            responseValue    [11] OCTET STRING OPTIONAL }
 * </pre>
 * 
 * where the responseName is not present, and the responseValue contains
 * a BER encoded value, defined by the following grammar :
 * 
 * <pre>
 * txnEndRes ::= SEQUENCE {
 *         messageID MessageID OPTIONAL,
 *              -- msgid associated with non-success resultCode
 *         updatesControls SEQUENCE OF updateControls SEQUENCE {
 *              messageID MessageID,
 *                   -- msgid associated with controls
 *              controls  Controls
 *         } OPTIONAL
 *    }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface EndTransactionResponse extends ExtendedResponse
{
    /** The OID for the Start Transaction extended operation response. */
    String EXTENSION_OID = EndTransactionRequest.EXTENSION_OID;
    
    
    /**
     * @return The Message ID if failure
     */
    int getFailedMessageId();
    
    
    /**
     * @param failedMessageId The messageId that causes the failure
     */
    void setFailedMessageId( int failedMessageId );
    
    
    /**
     * @return the list of <messageId, Controls> processed within the transaction 
     */
    List<UpdateControls> getUpdateControls();
}