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

package org.apache.directory.api.ldap.extras.controls.ppolicy_impl;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyResponse;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyResponseImpl;


/**
 * container for PasswordPolicyResponseControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordPolicyResponseContainer extends AbstractContainer
{
    private PasswordPolicyResponse control;


    /**
     * Creates a new StoredProcedureContainer instance
     * 
     * @param codec The LDAP Service to use
     */
    public PasswordPolicyResponseContainer( LdapApiService codec )
    {
        super();
        control = new PasswordPolicyResponseDecorator( codec, new PasswordPolicyResponseImpl() );
        setGrammar( PasswordPolicyResponseGrammar.getInstance() );
        setTransition( PasswordPolicyResponseStates.START_STATE );
    }


    /**
     * Creates a new StoredProcedureContainer instance
     * 
     * @param codec The LDAP Service to use
     * @param ppolicyResponse The PasswordPolicy response
     */
    public PasswordPolicyResponseContainer( LdapApiService codec, PasswordPolicyResponse ppolicyResponse )
    {
        super();

        control = new PasswordPolicyResponseDecorator( codec, ppolicyResponse );

        setGrammar( PasswordPolicyResponseGrammar.getInstance() );
        setTransition( PasswordPolicyResponseStates.START_STATE );
    }


    /**
     * @return the PasswordPolicyResponseControlCodec object
     */
    public PasswordPolicyResponse getPasswordPolicyResponseControl()
    {
        return control;
    }


    /**
     * Sets the password policy control
     * 
     * @param control The decorated PasswordPolicy control
     */
    public void setPasswordPolicyResponseControl( PasswordPolicyResponseDecorator control )
    {
        this.control = control;
    }


    /**
     * clean the container
     */
    @Override
    public void clean()
    {
        super.clean();
        control = null;
    }

}
