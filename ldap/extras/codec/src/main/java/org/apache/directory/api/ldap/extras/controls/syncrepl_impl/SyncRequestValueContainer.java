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
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncInfoValue.SyncRequestValue;


/**
 * A container for the SyncRequestValue control
 *  
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SyncRequestValueContainer extends AbstractContainer
{
    /** SyncRequestValueControl */
    private SyncRequestValue control;


    /**
     * Creates a new SyncRequestValueControlContainer object. We will store one grammar,
     * it's enough ...
     */
    public SyncRequestValueContainer()
    {
        super();
        setGrammar( SyncRequestValueGrammar.getInstance() );
        setTransition( SyncRequestValueStatesEnum.START_STATE );
    }


    /**
     * Creates a new SyncRequestValueControlContainer object. We will store one grammar,
     * it's enough ...
     * 
     * @param control The control to store
     */
    public SyncRequestValueContainer( SyncRequestValue control )
    {
        super();
        this.control = control;
        setGrammar( SyncRequestValueGrammar.getInstance() );
        setTransition( SyncRequestValueStatesEnum.START_STATE );
    }


    /**
     * @return Returns the syncRequestValue control.
     */
    public SyncRequestValue getSyncRequestValueControl()
    {
        return control;
    }


    /**
     * Set a SyncRequestValueControl Object into the container. It will be completed by
     * the ldapDecoder.
     * 
     * @param control the SyncRequestValueControl to set.
     */
    public void setSyncRequestValueControl( SyncRequestValue control )
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
