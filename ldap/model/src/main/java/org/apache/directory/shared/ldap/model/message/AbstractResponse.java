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
package org.apache.directory.shared.ldap.model.message;

import org.apache.directory.shared.ldap.model.exception.LdapAliasException;
import org.apache.directory.shared.ldap.model.exception.LdapAttributeInUseException;
import org.apache.directory.shared.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.shared.ldap.model.exception.LdapContextNotEmptyException;
import org.apache.directory.shared.ldap.model.exception.LdapEntryAlreadyExistsException;
import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.exception.LdapNoPermissionException;
import org.apache.directory.shared.ldap.model.exception.LdapNoSuchAttributeException;
import org.apache.directory.shared.ldap.model.exception.LdapNoSuchObjectException;
import org.apache.directory.shared.ldap.model.exception.LdapOperationException;
import org.apache.directory.shared.ldap.model.exception.LdapSchemaViolationException;
import org.apache.directory.shared.ldap.model.exception.LdapUnwillingToPerformException;


/**
 * Abstract base for a Response message.
 * 
 * @author <a href="mailto:dev@directory.apache.org"> Apache Directory Project</a>
 */
public abstract class AbstractResponse extends AbstractMessage implements Response
{
    // ------------------------------------------------------------------------
    // Response Interface Method Implementations
    // ------------------------------------------------------------------------

    /**
     * Allows subclasses based on the abstract type to create a response to a
     * request.
     * 
     * @param id the response eliciting this Request
     * @param type the message type of the response
     */
    protected AbstractResponse( final int id, final MessageTypeEnum type )
    {
        super( id, type );
    }
    
    
    /**
     * Process the response, throwing the associated exception if needed. If the result
     * was SUCCESS, does not return anything but true. 
     * 
     * @param response The response to process
     * @return For the COMPARE_TRUE or COMPARE_FALSE results, return true or false
     * @throws LdapException The associated exception
     */
    public static boolean processResponse( ResultResponse response ) throws LdapException
    {
        LdapResult ldapResult = response.getLdapResult();
        
        switch ( ldapResult.getResultCode() )
        {
            case SUCCESS :
                return true;
                
            case COMPARE_TRUE :
                return true;
                
            case COMPARE_FALSE :
                return false;
                
            case INVALID_CREDENTIALS :
                LdapAuthenticationException authenticationException = new LdapAuthenticationException( ldapResult.getDiagnosticMessage() );
                authenticationException.setResolvedDn( ldapResult.getMatchedDn() );
                
                throw authenticationException;
                
            case UNWILLING_TO_PERFORM :
                LdapUnwillingToPerformException unwillingToPerformException = new LdapUnwillingToPerformException( ldapResult.getDiagnosticMessage() );
                unwillingToPerformException.setResolvedDn( ldapResult.getMatchedDn() );
                
                throw unwillingToPerformException;
                
            case INSUFFICIENT_ACCESS_RIGHTS :
                LdapNoPermissionException ldapNoPermissionException = new LdapNoPermissionException( ldapResult.getDiagnosticMessage() );
                ldapNoPermissionException.setResolvedDn( ldapResult.getMatchedDn() );
                
                throw ldapNoPermissionException;
                
            case NOT_ALLOWED_ON_NON_LEAF :
                LdapContextNotEmptyException ldapContextNotEmptyException = new LdapContextNotEmptyException( ldapResult.getDiagnosticMessage() );
                ldapContextNotEmptyException.setResolvedDn( ldapResult.getMatchedDn() );
                
                throw ldapContextNotEmptyException;
                
            case NO_SUCH_OBJECT :
                LdapNoSuchObjectException ldapNoSuchObjectException = new LdapNoSuchObjectException( ldapResult.getDiagnosticMessage() );
                ldapNoSuchObjectException.setResolvedDn( ldapResult.getMatchedDn() );
                
                throw ldapNoSuchObjectException;
                
            case NO_SUCH_ATTRIBUTE :
                LdapNoSuchAttributeException ldapNoSuchAttributeException = new LdapNoSuchAttributeException( ldapResult.getDiagnosticMessage() );
                ldapNoSuchAttributeException.setResolvedDn( ldapResult.getMatchedDn() );
                
                throw ldapNoSuchAttributeException;
                
            case ATTRIBUTE_OR_VALUE_EXISTS :
                LdapAttributeInUseException ldapAttributeInUseException = new LdapAttributeInUseException( ldapResult.getDiagnosticMessage() );
                ldapAttributeInUseException.setResolvedDn( ldapResult.getMatchedDn() );
                
                throw ldapAttributeInUseException;
                
            case ENTRY_ALREADY_EXISTS :
                LdapEntryAlreadyExistsException ldapEntryAlreadyExistsException = new LdapEntryAlreadyExistsException( ldapResult.getDiagnosticMessage() );
                ldapEntryAlreadyExistsException.setResolvedDn( ldapResult.getMatchedDn() );
                
                throw ldapEntryAlreadyExistsException;
                
            case OBJECT_CLASS_VIOLATION :
            case NOT_ALLOWED_ON_RDN :
            case OBJECT_CLASS_MODS_PROHIBITED :
                LdapSchemaViolationException ldapSchemaViolationException = 
                    new LdapSchemaViolationException( ldapResult.getResultCode() , ldapResult.getDiagnosticMessage() );
                ldapSchemaViolationException.setResolvedDn( ldapResult.getMatchedDn() );
                
                throw ldapSchemaViolationException;
                
            case ALIAS_PROBLEM :
                LdapAliasException ldapAliasException = new LdapAliasException( ldapResult.getDiagnosticMessage() );
                ldapAliasException.setResolvedDn( ldapResult.getMatchedDn() );
                
                throw ldapAliasException;
                
            case REFERRAL :
                // TODO
                
            default :
                LdapOperationException exception = new LdapOperationException( ldapResult.getResultCode(), ldapResult.getDiagnosticMessage() );
                exception.setResolvedDn( ldapResult.getMatchedDn() );
                
                throw exception;
        }
    }
}
