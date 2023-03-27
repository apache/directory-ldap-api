/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.ldap.client.template;


import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyResponse;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyResponseImpl;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.ResultResponse;
import org.apache.directory.ldap.client.template.exception.PasswordException;


/**
 * A base, abstract, implementation of <code>PasswordPolicyResponder</code>.  
 * Extend this class and override success(PasswordPolicy), 
 * fail(ResultResponse, PasswordPolicy, ResultCodeEnum), or
 * exception(LdapException).  If that does not offer enough
 * flexibility, you must implement PasswordPolicyResponder yourself.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractPasswordPolicyResponder implements PasswordPolicyResponder
{
    private final PasswordPolicyResponse passwordPolicyResponseControl;


    protected AbstractPasswordPolicyResponder( LdapApiService ldapApiService )
    {
        this.passwordPolicyResponseControl = new PasswordPolicyResponseImpl();
    }
    
    
    /**
     * Translates an <code>LdapException</code> to a 
     * <code>PasswordException</code> to be thrown when 
     * {@link #process(PasswordPolicyOperation)} fails.
     * 
     * @param e The exception to set
     * @return The created PasswordException
     */
    protected PasswordException exception( LdapException e )
    {
        return new PasswordException().setLdapException( e );
    }
    
    
    /**
     * Returns an exception to be thrown in the case of a non SUCCESS 
     * <code>resultCode</code>.
     * 
     * @param resultResponse The result response
     * @param passwordPolicyResponse The password policy in use
     * @param resultCode The result
     * @return The created PasswordException
     */
    protected PasswordException fail( ResultResponse resultResponse, 
            PasswordPolicyResponse passwordPolicyResponse, ResultCodeEnum resultCode )
    {
        String diagnosticMessage = "";
        
        if  ( ( resultResponse != null ) && resultResponse.getLdapResult() != null )
        {
            diagnosticMessage = resultResponse.getLdapResult().getDiagnosticMessage();
        }

        PasswordException exception = new PasswordException( diagnosticMessage );
        exception.setResultCode( resultCode );
        
        if ( passwordPolicyResponse != null
            && passwordPolicyResponse.getPasswordPolicyError() != null )
        {
            exception.setPasswordPolicyError( passwordPolicyResponse.getPasswordPolicyError() );
        }
        return exception;
    }


    private PasswordPolicyResponse getPasswordPolicy( Response response )
    {
        Control control = response.getControls().get( passwordPolicyResponseControl.getOid() );
        
        return control == null
            ? null
            : ( PasswordPolicyResponse ) control;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public final PasswordWarning process( PasswordPolicyOperation operation )
        throws PasswordException
    {
        try
        {
            ResultResponse response = operation.process();
            PasswordPolicyResponse passwordPolicyResponse = getPasswordPolicy( response );
            ResultCodeEnum resultCode = response.getLdapResult().getResultCode();
            
            if ( resultCode == ResultCodeEnum.SUCCESS )
            {
                return success( passwordPolicyResponse );
            }
            else
            {
                throw fail( response, passwordPolicyResponse, resultCode );
            }
        }
        catch ( LdapException e )
        {
            throw new PasswordException().setLdapException( e );
        }
    }
    
    /**
     * Returns a <code>PasswordWarning</code>, or <code>null</code> if no 
     * warnings were present in the supplied <code>passwordPolicy</code>.
     * 
     * @param passwordPolicyResponse The PasswordPolicyReponse in use
     * @return The created PasswordWarning
     */
    protected PasswordWarning success( PasswordPolicyResponse passwordPolicyResponse ) 
    {
        return passwordPolicyResponse == null
                ? null
                : PasswordWarningImpl.newWarning( passwordPolicyResponse );
    }
}
