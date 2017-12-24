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
package org.apache.directory.api.ldap.extras.controls.ad_impl;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ad.AdPolicyHints;


/**
 * A container for the AdPolicyHints request control.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AdPolicyHintsContainer extends AbstractContainer
{
    private AdPolicyHintsDecorator control;

    private LdapApiService codec;


    /**
     * Creates a new AdPolicyHintsContainer instance
     *
     * @param codec The LDAP Service to use
     */
    public AdPolicyHintsContainer( LdapApiService codec )
    {
        super();
        this.codec = codec;
        setGrammar( AdPolicyHintsGrammar.getInstance() );
        setTransition( AdPolicyHintsStates.START_STATE );
    }


    /**
     * Creates a new AdPolicyHintsContainer instance
     *
     * @param control The AdPolicyHints control
     * @param codec The LDAP Service to use
     */
    public AdPolicyHintsContainer( AdPolicyHintsDecorator control, LdapApiService codec )
    {
        this( codec );
        decorate( control );
    }


    /**
     * @return The AdPolicyHints control
     */
    public AdPolicyHintsDecorator getDecorator()
    {
        return control;
    }


    /**
     * Decorate the AdPolicyHints control
     *
     * @param control The control to decorate
     */
    public void decorate( AdPolicyHints control )
    {
        if ( control instanceof AdPolicyHintsDecorator )
        {
            this.control = ( AdPolicyHintsDecorator ) control;
        }
        else
        {
            this.control = new AdPolicyHintsDecorator( codec, control );
        }
    }


    /**
     * Sets the AdPolicyHints control
     *
     * @param control The AdPolicyHints control
     */
    public void setAdPolicyHintsRequestControl( AdPolicyHintsDecorator control )
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