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
package org.apache.directory.api.ldap.extras.controls.syncrepl_impl;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncState.SyncStateValue;


/**
 * A container for the SyncStateValue control
 *  
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SyncStateValueContainer extends AbstractContainer
{
    /** SyncStateValueControl */
    private SyncStateValue control;


    /**
     * Creates a new SyncStateValueControlContainer object. We will store one grammar,
     * it's enough ...
     */
    public SyncStateValueContainer()
    {
        super();
        setGrammar( SyncStateValueGrammar.getInstance() );
        setTransition( SyncStateValueStatesEnum.START_STATE );
    }


    /**
     * Creates a new SyncStateValueControlContainer object. We will store one grammar,
     * it's enough ...
     * 
     * @param control The control to store
     */
    public SyncStateValueContainer( SyncStateValue control )
    {
        super();
        this.control = control;
        setGrammar( SyncStateValueGrammar.getInstance() );
        setTransition( SyncStateValueStatesEnum.START_STATE );
    }


    /**
     * @return Returns the syncStateValue control.
     */
    public SyncStateValue getSyncStateValueControl()
    {
        return control;
    }


    /**
     * Set a SyncStateValueControl Object into the container. It will be completed by
     * the ldapDecoder.
     * 
     * @param control the SyncStateValueControl to set.
     */
    public void setSyncStateValueControl( SyncStateValue control )
    {
        this.control = control;
    }


    /**
     * Clean the container
     */
    @Override
    public void clean()
    {
        super.clean();
        control = null;
    }
}
