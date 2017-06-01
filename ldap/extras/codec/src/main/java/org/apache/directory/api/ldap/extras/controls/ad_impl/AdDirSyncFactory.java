/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.ldap.extras.controls.ad_impl;


import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSync;


/**
 * A {@link ControlFactory} which creates {@link AdDirSync} controls.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class AdDirSyncFactory implements ControlFactory<AdDirSync>
{
    /** The codec for this factory */
    private LdapApiService codec;


    /**
     * Creates a new instance of AdDirSyncFactory.
     *
     * @param codec The codec for this factory.
     */
    public AdDirSyncFactory( LdapApiService codec )
    {
        this.codec = codec;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return AdDirSync.OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CodecControl<AdDirSync> newCodecControl()
    {
        return new AdDirSyncDecorator( codec );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CodecControl<AdDirSync> newCodecControl( AdDirSync control )
    {
        return new AdDirSyncDecorator( codec, control );
    }
}
