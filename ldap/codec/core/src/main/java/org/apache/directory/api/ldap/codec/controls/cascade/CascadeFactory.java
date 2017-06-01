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
package org.apache.directory.api.ldap.codec.controls.cascade;


import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.controls.Cascade;
import org.apache.directory.api.ldap.model.message.controls.CascadeImpl;


/**
 * A codec {@link ControlFactory} implementation for {@link Cascade} controls.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class CascadeFactory implements ControlFactory<Cascade>
{
    /** The LDAP codec responsible for encoding and decoding Cascade Controls */
    private LdapApiService codec;


    /**
     * Creates a new instance of CascadeFactory.
     *
     * @param codec The LDAP codec
     */
    public CascadeFactory( LdapApiService codec )
    {
        this.codec = codec;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return Cascade.OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CodecControl<Cascade> newCodecControl()
    {
        return new CascadeDecorator( codec, new CascadeImpl() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CodecControl<Cascade> newCodecControl( Cascade control )
    {
        return new CascadeDecorator( codec, control );
    }
}
