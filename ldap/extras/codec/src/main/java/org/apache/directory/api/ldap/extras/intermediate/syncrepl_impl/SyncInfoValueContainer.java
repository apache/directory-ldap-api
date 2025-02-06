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
package org.apache.directory.api.ldap.extras.intermediate.syncrepl_impl;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.extras.intermediate.syncrepl.SyncInfoValue;


/**
 * A container for the SyncInfoValue message
 *  
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SyncInfoValueContainer extends AbstractContainer
{
    /** SyncInfoValue */
    private SyncInfoValue syncInfoValue;


    /**
     * Creates a new SyncInfoValueContainer object.
     * 
     * @param syncInfoValue The syncInfoValue to store
     */
    public SyncInfoValueContainer( SyncInfoValue syncInfoValue )
    {
        super();
        this.syncInfoValue = syncInfoValue;
        setGrammar( SyncInfoValueGrammar.getInstance() );
        setTransition( SyncInfoValueStatesEnum.START_STATE );
    }


    /**
     * Get the syncInfoValue instance
     * 
     * @return Returns the syncInfoValue instance.
     */
    public SyncInfoValue getSyncInfoValue()
    {
        return syncInfoValue;
    }


    /**
     * Set a SyncInfoValue Object into the container. It will be completed by
     * the ldapDecoder.
     * 
     * @param syncInfoValue the SyncInfoValueCodec to set.
     */
    public void setSyncInfoValue( SyncInfoValue syncInfoValue )
    {
        this.syncInfoValue = syncInfoValue;
    }


    /**
     * Clean the container
     */
    @Override
    public void clean()
    {
        super.clean();
        syncInfoValue = null;
    }
}
