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
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncRequest;


/**
 *
 * ASN.1 container for AD DirSyncRequest control.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AdDirSyncRequestContainer extends AbstractContainer
{
    /** adDirSync request */
    private AdDirSyncRequest control;

    private LdapApiService codec;


    /**
     * Creates a new AdDirSyncRequestControl Container object.
     *
     * @param codec The LDAP Service to use
     */
    public AdDirSyncRequestContainer( LdapApiService codec )
    {
        super();
        this.codec = codec;
        this.control = new AdDirSyncRequestDecorator( codec );
        setGrammar( AdDirSyncRequestGrammar.getInstance() );
        setTransition( AdDirSyncRequestStatesEnum.START_STATE );
    }


    /**
     * Creates a new AdDirSyncRequestControl object.
     *
     * @param codec The LDAP Service to use
     * @param control The AdDirSyncRequest control to decorate
     */
    public AdDirSyncRequestContainer( LdapApiService codec, AdDirSyncRequest control )
    {
        super();
        this.codec = codec;
        this.control = control;
        setGrammar( AdDirSyncRequestGrammar.getInstance() );
        setTransition( AdDirSyncRequestStatesEnum.START_STATE );
    }


    /**
     * @return the AdDirSyncRequestControlCodec object
     */
    public AdDirSyncRequest getAdDirSyncRequestControl()
    {
        return control;
    }


    /**
     * Set a AdDirSyncRequestControlCodec Object into the container. It will be completed
     * by the ldapDecoder.
     *
     * @param control the AdDirSyncRequestControlCodec to set.
     */
    public void setAdDirSyncRequestControl( AdDirSyncRequest control )
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
