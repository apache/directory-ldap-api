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
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncInfoValue.SyncInfoValue;


/**
 * A container for the SyncInfoValue control
 *  
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SyncInfoValueContainer extends AbstractContainer
{
    /** SyncInfoValueControl */
    private SyncInfoValue control;

    private LdapApiService codec;


    /**
     * Creates a new SyncInfoValueControlContainer object. We will store one grammar,
     * it's enough ...
     * 
     * @param codec The LDAP Service to use
     */
    public SyncInfoValueContainer( LdapApiService codec )
    {
        super();
        this.codec = codec;
        this.control = new SyncInfoValueDecorator( codec );
        setGrammar( SyncInfoValueGrammar.getInstance() );
        setTransition( SyncInfoValueStatesEnum.START_STATE );
    }


    /**
     * Creates a new SyncInfoValueControlContainer object. We will store one grammar,
     * it's enough ...
     * 
     * @param codec The LDAP Service to use
     * @param control The control to decorate
     */
    public SyncInfoValueContainer( LdapApiService codec, SyncInfoValue control )
    {
        super();
        this.codec = codec;
        this.control = control;
        setGrammar( SyncInfoValueGrammar.getInstance() );
        setTransition( SyncInfoValueStatesEnum.START_STATE );
    }


    /**
     * @return Returns the syncInfoValue control.
     */
    public SyncInfoValue getSyncInfoValueControl()
    {
        return control;
    }


    /**
     * Set a SyncInfoValueControl Object into the container. It will be completed by
     * the ldapDecoder.
     * 
     * @param control the SyncInfoValueControlCodec to set.
     */
    public void setSyncInfoValueControl( SyncInfoValue control )
    {
        this.control = control;
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
        control = null;
    }
}
