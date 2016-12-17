/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicy;
import org.apache.directory.api.ldap.extras.controls.ppolicy_impl.PasswordPolicyDecorator;
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
    private final PasswordPolicyDecorator passwordPolicyRequestControl;


    protected AbstractPasswordPolicyResponder( LdapApiService ldapApiService )
    {
        this.passwordPolicyRequestControl = new PasswordPolicyDecorator(
            ldapApiService );
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
     * @param passwordPolicy The password policy in use
     * @param resultCode The result
     * @return The created PasswordException
     */
    protected PasswordException fail( ResultResponse resultResponse, 
            PasswordPolicy passwordPolicy, ResultCodeEnum resultCode )
    {
        PasswordException exception = new PasswordException();
        exception.setResultCode( resultCode );
        if ( passwordPolicy != null
            && passwordPolicy.getResponse() != null
            && passwordPolicy.getResponse().getPasswordPolicyError() != null )
        {
            exception.setPasswordPolicyError( passwordPolicy.getResponse().getPasswordPolicyError() );
        }
        return exception;
    }


    private PasswordPolicy getPasswordPolicy( Response response )
    {
        Control control = response.getControls().get( passwordPolicyRequestControl.getOid() );
        return control == null
            ? null
            : ( ( PasswordPolicyDecorator ) control ).getDecorated();
    }


    @Override
    public final PasswordWarning process( PasswordPolicyOperation operation )
        throws PasswordException
    {
        try
        {
            ResultResponse response = operation.process();
            PasswordPolicy passwordPolicy = getPasswordPolicy( response );
            ResultCodeEnum resultCode = response.getLdapResult().getResultCode();
            if ( resultCode == ResultCodeEnum.SUCCESS )
            {
                return success( passwordPolicy );
            }
            else
            {
                throw fail( response, passwordPolicy, resultCode );
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
     * @param passwordPolicy The PasswordPolicy in use
     * @return The created PasswordWarning
     */
    protected PasswordWarning success( PasswordPolicy passwordPolicy ) 
    {
        return passwordPolicy == null
                ? null
                : PasswordWarningImpl.newWarning( passwordPolicy );
    }
}
