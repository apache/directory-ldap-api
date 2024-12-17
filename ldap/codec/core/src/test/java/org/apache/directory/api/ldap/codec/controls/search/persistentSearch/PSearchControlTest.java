/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.directory.api.ldap.codec.controls.search.persistentSearch;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.controls.ChangeType;
import org.apache.directory.api.ldap.model.message.controls.PersistentSearch;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the PSearchControlTest codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class PSearchControlTest extends AbstractCodecServiceTest
{
    /**
     * Test encoding of a PSearchControl.
     * 
     * @throws Exception If the ASN1 decoding failed
     */
    @Test
    public void testEncodePSearchControl() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0B );
        bb.put( new byte[]
            {
                0x30, 0x09,             // PersistentSearch ::= SEQUENCE {
                0x02, 0x01, 0x01,       // changeTypes INTEGER,
                0x01, 0x01, 0x00,       // changesOnly BOOLEAN,
                0x01, 0x01, 0x00        // returnECs BOOLEAN
        } );

        bb.flip();

        PersistentSearchFactory factory = ( PersistentSearchFactory ) codec.getRequestControlFactories().
            get( PersistentSearch.OID );
        PersistentSearch ctrl = factory.newControl();
        factory.decodeValue( ctrl, bb.array() );

        ctrl.setChangesOnly( false );
        ctrl.setReturnECs( false );
        ctrl.setChangeTypes( 1 );

        // Test reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, ctrl );

        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PSearchControl with combined changes types
     * 
     * @throws Exception If the ASN1 decoding failed
     */
    @Test
    public void testDecodeModifyDNRequestSuccessChangeTypesAddModDN() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0b );
        bb.put( new byte[]
            {
                0x30, 0x09,             // PersistentSearch ::= SEQUENCE {
                0x02, 0x01, 0x09,       // changeTypes INTEGER,
                0x01, 0x01, 0x00,       // changesOnly BOOLEAN,
                0x01, 0x01, 0x00        // returnECs BOOLEAN
        } );
        bb.flip();

        PersistentSearchFactory factory = ( PersistentSearchFactory ) codec.getRequestControlFactories().
            get( PersistentSearch.OID );
        PersistentSearch ctrl = factory.newControl();
        factory.decodeValue( ctrl, bb.array() );

        int changeTypes = ctrl.getChangeTypes();
        assertTrue( ChangeType.ADD.presentIn( changeTypes ) );
        assertTrue( ChangeType.MODDN.presentIn( changeTypes ) );
        assertEquals( false, ctrl.isChangesOnly() );
        assertEquals( false, ctrl.isReturnECs() );

        // Test reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, ctrl );

        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PSearchControl with a changes types which
     * value is 0
     * 
     * @throws Exception If the ASN1 decoding failed
     */
    @Test
    public void testDecodeModifyDNRequestSuccessChangeTypes0() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0b );
        bb.put( new byte[]
            {
                0x30, 0x09,             // PersistentSearch ::= SEQUENCE {
                0x02, 0x01, 0x00,       // changeTypes INTEGER,
                0x01, 0x01, 0x00,       // changesOnly BOOLEAN,
                0x01, 0x01, 0x00        // returnECs BOOLEAN
        } );
        bb.flip();

        PersistentSearchFactory factory = ( PersistentSearchFactory ) codec.getRequestControlFactories().
            get( PersistentSearch.OID );
        PersistentSearch ctrl = factory.newControl();

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( ctrl, bb.array() );
        } );
    }


    /**
     * Test the decoding of a PSearchControl with a changes types which
     * value is above 15
     * 
     * @throws Exception If the ASN1 decoding failed
     */
    @Test
    public void testDecodeModifyDNRequestSuccessChangeTypes22() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0b );
        bb.put( new byte[]
            {
                0x30, 0x09,             // PersistentSearch ::= SEQUENCE {
                0x02, 0x01, 0x22,       // changeTypes INTEGER,
                0x01, 0x01, 0x00,       // changesOnly BOOLEAN,
                0x01, 0x01, 0x00        // returnECs BOOLEAN
        } );
        bb.flip();

        PersistentSearchFactory factory = ( PersistentSearchFactory ) codec.getRequestControlFactories().
            get( PersistentSearch.OID );
        PersistentSearch ctrl = factory.newControl();

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( ctrl, bb.array() );
        } );
    }


    /**
     * Test the decoding of a PSearchControl with a null sequence
     * 
     * @throws Exception If the ASN1 decoding failed
     */
    @Test
    public void testDecodeModifyDNRequestSuccessNullSequence() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );
        bb.put( new byte[]
            {
                0x30, 0x00          // PersistentSearch ::= SEQUENCE {
            } );
        bb.flip();

        PersistentSearchFactory factory = ( PersistentSearchFactory ) codec.getRequestControlFactories().
            get( PersistentSearch.OID );
        PersistentSearch ctrl = factory.newControl();

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( ctrl, bb.array() );
        } );
    }


    /**
     * Test the decoding of a PSearchControl without changeTypes
     * 
     * @throws Exception If the ASN1 decoding failed
     */
    @Test
    public void testDecodeModifyDNRequestSuccessWithoutChangeTypes() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            {
                0x30, 0x06,             // PersistentSearch ::= SEQUENCE {
                  0x01, 0x01, 0x00,     // changesOnly BOOLEAN,
                  0x01, 0x01, 0x00      // returnECs BOOLEAN
        } );
        bb.flip();

        PersistentSearchFactory factory = ( PersistentSearchFactory ) codec.getRequestControlFactories().
            get( PersistentSearch.OID );
        PersistentSearch ctrl = factory.newControl();

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( ctrl, bb.array() );
        } );
    }


    /**
     * Test the decoding of a PSearchControl without changeOnly
     * 
     * @throws Exception If the ASN1 decoding failed
     */
    @Test
    public void testDecodeModifyDNRequestSuccessWithoutChangesOnly() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            {
                0x30, 0x06,             // PersistentSearch ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // changeTypes INTEGER,
                  0x01, 0x01, 0x00      // returnECs BOOLEAN
        } );
        bb.flip();

        PersistentSearchFactory factory = ( PersistentSearchFactory ) codec.getRequestControlFactories().
            get( PersistentSearch.OID );
        PersistentSearch ctrl = factory.newControl();

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( ctrl, bb.array() );
        } );
    }


    /**
     * Test the decoding of a PSearchControl without returnECs
     * 
     * @throws Exception If the ASN1 decoding failed
     */
    @Test
    public void testDecodeModifyDNRequestSuccessWithoutReturnECs() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            {
                0x30, 0x06,             // PersistentSearch ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // changeTypes INTEGER,
                  0x01, 0x01, 0x00      // changesOnly BOOLEAN,
            } );
        bb.flip();

        PersistentSearchFactory factory = ( PersistentSearchFactory ) codec.getRequestControlFactories().
            get( PersistentSearch.OID );
        PersistentSearch ctrl = factory.newControl();

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( ctrl, bb.array() );
        } );
    }
}
