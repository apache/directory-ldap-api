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
package org.apache.directory.api.ldap.extras.intermediate.syncrepl_impl;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
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

    /** The LDAP Service instance */
    private LdapApiService codec;


    /**
     * Creates a new SyncInfoValueContainer object. We will store one grammar,
     * it's enough ...
     * 
     * @param codec The LDAP Service to use
     */
    public SyncInfoValueContainer( LdapApiService codec )
    {
        super();
        this.codec = codec;
        this.syncInfoValue = new SyncInfoValueDecorator( codec );
        setGrammar( SyncInfoValueGrammar.getInstance() );
        setTransition( SyncInfoValueStatesEnum.START_STATE );
    }


    /**
     * Creates a new SyncInfoValueContainer object. We will store one grammar,
     * it's enough ...
     * 
     * @param codec The LDAP Service to use
     * @param syncInfoValue The syncInfoValue to decorate
     */
    public SyncInfoValueContainer( LdapApiService codec, SyncInfoValue syncInfoValue )
    {
        super();
        this.codec = codec;
        this.syncInfoValue = syncInfoValue;
        setGrammar( SyncInfoValueGrammar.getInstance() );
        setTransition( SyncInfoValueStatesEnum.START_STATE );
    }


    /**
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
     * @return The LDAP API service
     */
    public LdapApiService getCodecService()
    {
        return codec;
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
