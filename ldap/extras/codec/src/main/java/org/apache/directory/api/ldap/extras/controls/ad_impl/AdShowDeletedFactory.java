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


import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractControlFactory;
import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ad.AdShowDeleted;
import org.apache.directory.api.ldap.extras.controls.ad.AdShowDeletedImpl;
import org.apache.directory.api.ldap.model.message.Control;


/**
 * A codec {@link ControlFactory} implementation for {@link AdShowDeleted} controls.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class AdShowDeletedFactory extends AbstractControlFactory<AdShowDeleted>
{
    /**
     * Creates a new instance of AdDeletedFactory.
     *
     * @param codec The LDAP codec
     */
    public AdShowDeletedFactory( LdapApiService codec )
    {
        super( codec );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return AdShowDeleted.OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CodecControl<AdShowDeleted> newCodecControl()
    {
        return new AdShowDeletedDecorator( codec, new AdShowDeletedImpl() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CodecControl<AdShowDeleted> newCodecControl( AdShowDeleted control )
    {
        return new AdShowDeletedDecorator( codec, control );
    }


    @Override
    public void encodeValue( Asn1Buffer buffer, Control control )
    {
        // TODO Auto-generated method stub

    }
}
