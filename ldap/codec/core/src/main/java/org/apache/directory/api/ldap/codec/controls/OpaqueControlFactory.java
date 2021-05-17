/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.ldap.codec.controls;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractControlFactory;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.controls.OpaqueControl;

/**
 * A codec {@link ControlFactory} implementation for opaque controls.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class OpaqueControlFactory extends AbstractControlFactory<Control>
{
    /** 
     * Creates a new instance of OpaqueControlFactory.
     *
     * @param codec The LDAP codec.
     * @param oid The Control's OID
     */
    public OpaqueControlFactory( LdapApiService codec, String oid )
    {
        super( codec, oid );
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public Control newControl()
    {
        return new OpaqueControl( getOid() );
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, Control control )
    {
        buffer.put( ( ( OpaqueControl ) control ).getEncodedValue() );
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( Control control, byte[] controlBytes ) throws DecoderException
    {
        ( ( OpaqueControl ) control ).setEncodedValue( controlBytes );
    }
}
