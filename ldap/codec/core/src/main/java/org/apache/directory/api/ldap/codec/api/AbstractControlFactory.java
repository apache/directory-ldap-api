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
package org.apache.directory.api.ldap.codec.api;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Container;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.model.message.Control;

/**
 * A factory that encode the Control value
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @param <C> The Control type
 */
public abstract class AbstractControlFactory<C extends Control> implements ControlFactory<C>
{
    /** The LDAP codec responsible for encoding and decoding ManageDsaIT Control */
    protected LdapApiService codec;
    
    /** The control's OID */
    protected String oid;

    /**
     *
     * Creates a new instance of AbstractControlFactory.
     *
     * @param codec The LdapApiSevice instance
     * @param oid The control's OID
     */
    protected AbstractControlFactory( LdapApiService codec, String oid )
    {
        this.codec = codec;
        this.oid = oid;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return oid;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, Control control )
    {
        // Nothing to do by default
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( Control control, byte[] controlBytes ) throws DecoderException
    {
        // Nothing to do by default
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( ControlContainer container, Control control, byte[] controlBytes ) throws DecoderException
    {
        ByteBuffer buffer = ByteBuffer.wrap( controlBytes );
        container.setControl( control );
        Asn1Decoder.decode( buffer, ( Asn1Container ) container );
    }
}
