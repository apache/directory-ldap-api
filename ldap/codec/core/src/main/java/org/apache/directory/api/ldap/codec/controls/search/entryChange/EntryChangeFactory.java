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
package org.apache.directory.api.ldap.codec.controls.search.entryChange;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractControlFactory;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.controls.EntryChange;
import org.apache.directory.api.ldap.model.message.controls.EntryChangeImpl;


/**
 * A {@link ControlFactory} for {@link EntryChange} controls.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class EntryChangeFactory extends AbstractControlFactory<EntryChange>
{
    /** Default value when no change number is provided */
    public static final int UNDEFINED_CHANGE_NUMBER = -1;

    /**
     * Creates a new instance of EntryChangeFactory.
     *
     * @param codec The LDAP codec.
     */
    public EntryChangeFactory( LdapApiService codec )
    {
        super( codec, EntryChange.OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EntryChange newControl()
    {
        return new EntryChangeImpl();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, Control control )
    {
        int start = buffer.getPos();

        EntryChange entryChange = ( EntryChange ) control;

        // The changeNumber
        if ( entryChange.getChangeNumber() != UNDEFINED_CHANGE_NUMBER )
        {
            BerValue.encodeInteger( buffer, entryChange.getChangeNumber() );
        }

        // The previous DN if any
        if ( entryChange.getPreviousDn() != null )
        {
            BerValue.encodeOctetString( buffer, entryChange.getPreviousDn().getName() );
        }

        // The change type
        BerValue.encodeEnumerated( buffer, entryChange.getChangeType().getValue() );

        // The EntryChangeNotification sequence
        BerValue.encodeSequence( buffer, start );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( Control control, byte[] controlBytes ) throws DecoderException
    {
        decodeValue( new EntryChangeContainer( control ), control, controlBytes );
    }
}
