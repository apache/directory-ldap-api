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
package org.apache.directory.api.ldap.extras.controls.permissiveModify_impl;


import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.permissiveModify.PermissiveModify;
import org.apache.directory.api.ldap.extras.controls.permissiveModify.PermissiveModifyImpl;


/**
 * A codec {@link ControlFactory} implementation for {@link PermissiveModify} controls.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class PermissiveModifyFactory implements ControlFactory<PermissiveModify>
{
    /** The LDAP codec responsible for encoding and decoding PermissiveModify Controls */
    private LdapApiService codec;


    /**
     * Creates a new instance of PermissiveModifyFactory.
     *
     * @param codec The LDAP codec
     */
    public PermissiveModifyFactory( LdapApiService codec )
    {
        this.codec = codec;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return PermissiveModify.OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CodecControl<PermissiveModify> newCodecControl()
    {
        return new PermissiveModifyDecorator( codec, new PermissiveModifyImpl() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CodecControl<PermissiveModify> newCodecControl( PermissiveModify control )
    {
        return new PermissiveModifyDecorator( codec, control );
    }
}
