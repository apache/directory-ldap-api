/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.directory.api.ldap.extras.controls.ad;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.ldap.extras.controls.ad_impl.AdPolicyHintsFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 *
 * TestCase for AdPolicyHints Control.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class AdPolicyHintsControlTest
{
    private static LdapApiService codec;

    @BeforeAll
    public static void init()
    {
        codec = new DefaultLdapCodecService();
        codec.registerRequestControl( new AdPolicyHintsFactory( codec ) );
    }
    
    
    @Test
    public void testAdPolicyHiontsControlNoFlag() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );

        bb.put( new byte[]
            {
                0x30, 0x00                  // PolicyHintsRequestValue ::= SEQUENCE {
            } );

        bb.flip();

        AdPolicyHintsFactory factory = ( AdPolicyHintsFactory ) codec.getRequestControlFactories().
            get( AdPolicyHints.OID );
        AdPolicyHints adPolicyHints = factory.newControl();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( adPolicyHints, bb.array() );
        } );
    }


    @Test
    public void testAdPolicyHiontsControlEmptyFlag() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x04 );

        bb.put( new byte[]
            {
                0x30, 0x02,                  // PolicyHintsRequestValue ::= SEQUENCE {
                  0x02, 0x00                 //      Flags    INTEGER
            } );

        bb.flip();

        AdPolicyHintsFactory factory = ( AdPolicyHintsFactory ) codec.getRequestControlFactories().
            get( AdPolicyHints.OID );
        AdPolicyHints adPolicyHints = factory.newControl();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( adPolicyHints, bb.array() );
        } );
    }


    @Test
    public void testAdPolicyHintsControlLengthConstraintEnforced() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x05 );

        bb.put( new byte[]
            {
                0x30, 0x03,                  // PolicyHintsRequestValue ::= SEQUENCE {
                  0x02, 0x01, 0x01           //      Flags    INTEGER
            } );

        bb.flip();

        AdPolicyHintsFactory factory = ( AdPolicyHintsFactory ) codec.getRequestControlFactories().
            get( AdPolicyHints.OID );
        AdPolicyHints adPolicyHints = factory.newControl();
        factory.decodeValue( adPolicyHints, bb.array() );
        
        assertEquals( 1, adPolicyHints.getFlags() );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, adPolicyHints );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testAdPolicyHintsControlLengthConstraintNotEnforced() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x05 );

        bb.put( new byte[]
            {
                0x30, 0x03,                  // PolicyHintsRequestValue ::= SEQUENCE {
                  0x02, 0x01, 0x00           //      Flags    INTEGER
            } );

        bb.flip();

        AdPolicyHintsFactory factory = ( AdPolicyHintsFactory ) codec.getRequestControlFactories().
            get( AdPolicyHints.OID );
        AdPolicyHints adPolicyHints = factory.newControl();
        factory.decodeValue( adPolicyHints, bb.array() );
        
        assertEquals( 0, adPolicyHints.getFlags() );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, adPolicyHints );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }
}
