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
package org.apache.directory.api.ldap.extras.controls.policyHints_impl;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ad.policyHints.LdapServerPolicyHintsOid;


/**
 * A container for the LdapServerPolicyHintsOid request control.
 */
public class LdapServerPolicyHintsOidContainer extends AbstractContainer
{
    private LdapServerPolicyHintsOidDecorator control;

    private LdapApiService codec;


    /**
     * Creates a new LdapServerPolicyHintsOidContainer instance
     *
     * @param codec
     *            The LDAP Service to use
     */
    public LdapServerPolicyHintsOidContainer( LdapApiService codec )
    {
        super();
        this.codec = codec;
        setGrammar( LdapServerPolicyHintsOidGrammar.getInstance() );
        setTransition( LdapServerPolicyHintsOidStates.START_STATE );
    }


    /**
     * Creates a new VirtualListViewRequestContainer instance
     *
     * @param control
     *            The VLV control
     * @param codec
     *            The LDAP Service to use
     */
    public LdapServerPolicyHintsOidContainer( LdapServerPolicyHintsOidDecorator control, LdapApiService codec )
    {
        this( codec );
        decorate( control );
    }


    /**
     * @return The LdapServerPolicyHintsOid control
     */
    public LdapServerPolicyHintsOidDecorator getDecorator()
    {
        return control;
    }


    /**
     * Decorate the LdapServerPolicyHintsOid control
     *
     * @param control
     *            The control to decorate
     */
    public void decorate( LdapServerPolicyHintsOid control )
    {
        if ( control instanceof LdapServerPolicyHintsOidDecorator )
        {
            this.control = ( LdapServerPolicyHintsOidDecorator ) control;
        }
        else
        {
            this.control = new LdapServerPolicyHintsOidDecorator( codec, control );
        }
    }


    /**
     * Sets the LdapServerPolicyHintsOid control
     *
     * @param control
     *            The LdapServerPolicyHintsOid control
     */
    public void setLdapServerPolicyHintsOidRequestControl( LdapServerPolicyHintsOidDecorator control )
    {
        this.control = control;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clean()
    {
        super.clean();
        control = null;
    }
}