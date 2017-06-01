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
package org.apache.directory.api.ldap.extras.controls.syncrepl_impl;


import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncDone.SyncDoneValue;


/**
 * A {@link ControlFactory} which creates {@link SyncDoneValue} controls.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class SyncDoneValueFactory implements ControlFactory<SyncDoneValue>
{
    /** The codec for this factory */
    private LdapApiService codec;


    /**
     * Creates a new instance of SyncDoneValueFactory.
     *
     * @param codec The codec for this factory.
     */
    public SyncDoneValueFactory( LdapApiService codec )
    {
        this.codec = codec;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return SyncDoneValue.OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CodecControl<SyncDoneValue> newCodecControl()
    {
        return new SyncDoneValueDecorator( codec );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CodecControl<SyncDoneValue> newCodecControl( SyncDoneValue control )
    {
        return new SyncDoneValueDecorator( codec, control );
    }
}
