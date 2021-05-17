/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
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
import org.apache.directory.api.ldap.codec.api.ControlContainer;
import org.apache.directory.api.ldap.extras.controls.ad.AdPolicyHints;
import org.apache.directory.api.ldap.model.message.Control;


/**
 * A container for the AdPolicyHints request control.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AdPolicyHintsContainer extends AbstractContainer implements ControlContainer
{
    /** adPolicyHints request control */
    private Control control;

    /**
     * Creates a new AdPolicyHintsContainer instance
     *
     * @param control The AdPolicyHints control to store
     */
    public AdPolicyHintsContainer( Control control )
    {
        super();
        setGrammar( AdPolicyHintsGrammar.getInstance() );
        setTransition( AdPolicyHintsStates.START_STATE );
        this.control = control;
    }


    /**
     * @return The AdPolicyHints control
     */
    public AdPolicyHints getAdPolicyHints()
    {
        return ( AdPolicyHints ) control;
    }


    /**
     * Sets the AdPolicyHints control
     *
     * @param control The AdPolicyHints control
     */
    public void setControl( Control control )
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
