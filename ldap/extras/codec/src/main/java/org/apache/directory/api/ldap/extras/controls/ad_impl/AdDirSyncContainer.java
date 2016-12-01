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
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSync;


/**
 * 
 * ASN.1 container for AD DirSync control.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AdDirSyncContainer extends AbstractContainer
{
    /** adDirSync */
    private AdDirSync control;

    private LdapApiService codec;


    /**
     * Creates a new AdDirSyncControl Container object.
     *
     * @param codec The LDAP Service to use
     */
    public AdDirSyncContainer( LdapApiService codec )
    {
        super();
        this.codec = codec;
        this.control = new AdDirSyncDecorator( codec );
        setGrammar( AdDirSyncGrammar.getInstance() );
        setTransition( AdDirSyncStatesEnum.START_STATE );
    }


    /**
     * Creates a new AdDirSyncControl object.
     *
     * @param codec The LDAP Service to use
     * @param control The AdDirSync control to decorate
     */
    public AdDirSyncContainer( LdapApiService codec, AdDirSync control )
    {
        super();
        this.codec = codec;
        this.control = control;
        setGrammar( AdDirSyncGrammar.getInstance() );
        setTransition( AdDirSyncStatesEnum.START_STATE );
    }


    /**
     * @return the AdDirSyncControlCodec object
     */
    public AdDirSync getAdDirSyncControl()
    {
        return control;
    }


    /**
     * Set a AdDirSyncControlCodec Object into the container. It will be completed
     * by the ldapDecoder.
     * 
     * @param control the AdDirSyncControlCodec to set.
     */
    public void setAdDirSyncControl( AdDirSync control )
    {
        this.control = control;
    }


    /**
     * @return The LdapAPi service instance
     */
    public LdapApiService getCodecService()
    {
        return codec;
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
