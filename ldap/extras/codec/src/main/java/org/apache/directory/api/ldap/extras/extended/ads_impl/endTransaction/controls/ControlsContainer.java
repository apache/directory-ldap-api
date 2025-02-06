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
package org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction.controls;

import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.model.message.Control;

/**
 * A container storing decoded controls for a EndTransactionResponse extended operation
 *  
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ControlsContainer extends AbstractContainer
{
    /** The list of decoded controls */
    private List<Control> controls = new ArrayList<>();
    
    /** The current control */
    private Control currentControl;
    
    /** The control factory */
    private ControlFactory<?> factory;

    /** The codec service */
    private final LdapApiService codec;

    /**
     * A constructor for this container
     */
    public ControlsContainer()
    {
        super();
        setGrammar( ControlsGrammar.getInstance() );
        setTransition( ControlsStates.START_STATE );
        this.codec = LdapApiServiceFactory.getSingleton();
    }


    /**
     * Gets the {@link LdapApiService} associated with this Container.
     *
     * @return The LDAP service instance
     */
    public LdapApiService getLdapCodecService()
    {
        return codec;
    }

    
    /**
     * Get the current control
     * 
     * @return the currentControl
     */
    public Control getCurrentControl()
    {
        return currentControl;
    }


    /**
     * Set the current control
     * 
     * @param currentControl the currentControl to set
     */
    public void setCurrentControl( Control currentControl )
    {
        this.currentControl = currentControl;
    }


    /**
     * Get the controls list
     * 
     * @return the controls
     */
    public List<Control> getControls()
    {
        return controls;
    }
    

    /**
     * Add a control
     * 
     * @param control the controls to add to the list of controls
     */
    public void addControl( Control control )
    {
        controls.add( control );
    }


    /**
     * Get the control factory
     * 
     * @return the factory
     */
    public ControlFactory<?> getFactory()
    {
        return factory;
    }


    /**
     * Set the control factory
     * 
     * @param factory the factory to set
     */
    public void setFactory( ControlFactory<?> factory )
    {
        this.factory = factory;
    }
}
