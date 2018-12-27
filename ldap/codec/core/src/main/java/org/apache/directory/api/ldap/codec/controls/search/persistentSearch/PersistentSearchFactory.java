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
package org.apache.directory.api.ldap.codec.controls.search.persistentSearch;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.controls.PersistentSearch;
import org.apache.directory.api.ldap.model.message.controls.PersistentSearchImpl;


/**
 * A factory to create a PersistentSearch control
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class PersistentSearchFactory extends AbstractControlFactory<PersistentSearch>
{
    /**
     * Create a new PersistentSearchFactory instance
     *
     * @param codec The LdapApiService instance
     */
    public PersistentSearchFactory( LdapApiService codec )
    {
        super( codec, PersistentSearch.OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PersistentSearch newControl()
    {
        return new PersistentSearchImpl();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, Control control )
    {
        PersistentSearch persistentSearch = ( PersistentSearch ) control;
        int start = buffer.getPos();

        // The returnECs flag
        BerValue.encodeBoolean( buffer, persistentSearch.isReturnECs() );

        // The changeOnly flag
        BerValue.encodeBoolean( buffer, persistentSearch.isChangesOnly() );

        // The changeTypes
        BerValue.encodeInteger( buffer, persistentSearch.getChangeTypes() );

        // The PersistentSearch sequence
        BerValue.encodeSequence( buffer, start );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( Control control, byte[] controlBytes ) throws DecoderException
    {
        decodeValue( new PersistentSearchContainer( control ), control, controlBytes );
    }
}
