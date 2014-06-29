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
 * The default implementation of {@link PasswordPolicyResponder}.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordPolicyResponderImpl implements PasswordPolicyResponder
{
    private final PasswordPolicyDecorator passwordPolicyRequestControl;


    public PasswordPolicyResponderImpl( LdapApiService ldapApiService )
    {
        this.passwordPolicyRequestControl = new PasswordPolicyDecorator(
            ldapApiService );
    }


    private PasswordPolicy getPasswordPolicy( Response response )
    {
        Control control = response.getControls().get( passwordPolicyRequestControl.getOid() );
        return control == null
            ? null
            : ( ( PasswordPolicyDecorator ) control ).getDecorated();
    }


    @Override
    public PasswordWarning process( PasswordPolicyOperation operation )
        throws PasswordException
    {
        try
        {
            ResultResponse response = operation.process();
            PasswordPolicy passwordPolicy = getPasswordPolicy( response );

            ResultCodeEnum resultCode = response.getLdapResult().getResultCode();
            if ( resultCode == ResultCodeEnum.SUCCESS )
            {
                if ( passwordPolicy != null )
                {
                    return PasswordWarningImpl.newWarning( passwordPolicy );
                }
                return null;
            }
            else
            {
                PasswordException exception = new PasswordException();
                exception.setResultCode( resultCode );
                if ( passwordPolicy != null
                    && passwordPolicy.getResponse() != null
                    && passwordPolicy.getResponse().getPasswordPolicyError() != null )
                {
                    exception.setPasswordPolicyError( passwordPolicy.getResponse().getPasswordPolicyError() );
                }
                throw exception;
            }
        }
        catch ( LdapException e )
        {
            throw new PasswordException().setLdapException( e );
        }
    }
}
