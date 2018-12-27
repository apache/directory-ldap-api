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
package org.apache.directory.api.ldap.codec.controls.search.pagedSearch;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the PagedSearchControlTest codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class PagedSearchControlTest extends AbstractCodecServiceTest
{
    /**
     * Test encoding of a PagedSearchControl.
     */
    @Test
    public void testEncodePagedSearchControl() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0B );

        bb.put( new byte[]
            {
                0x30, 0x09,             // realSearchControlValue ::= SEQUENCE {
                  0x02, 0x01, 0x20,     // size INTEGER,
                  0x04, 0x04,
                    't', 'e', 's', 't'  // cookie OCTET STRING,
            } );

        bb.flip();

        PagedResultsFactory factory = ( PagedResultsFactory ) codec.getResponseControlFactories().get( PagedResults.OID );
        PagedResults pagedSearch = factory.newControl();
        factory.decodeValue( pagedSearch, bb.array() );

        assertEquals( 32, pagedSearch.getSize() );
        assertArrayEquals( Strings.getBytesUtf8( "test" ),
            pagedSearch.getCookie() );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, pagedSearch );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PagedSearchControl with no cookie
     */
    @Test(expected = DecoderException.class)
    public void testDecodePagedSearchRequestNoCookie() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x05 );
        bb.put( new byte[]
            {
                0x30, 0x03,             // realSearchControlValue ::= SEQUENCE {
                  0x02, 0x01, 0x20      // size INTEGER,
            } );
        bb.flip();

        PagedResultsFactory factory = ( PagedResultsFactory ) codec.getResponseControlFactories().get( PagedResults.OID );
        PagedResults pagedSearch = factory.newControl();
        factory.decodeValue( pagedSearch, bb.array() );
    }


    /**
     * Test the decoding of a PagedSearchControl with no size
     */
    @Test(expected = DecoderException.class)
    public void testDecodePagedSearchRequestNoSize() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            {
                0x30, 0x06,             // realSearchControlValue ::= SEQUENCE {
                  0x04, 0x04,
                    't', 'e', 's', 't'  // cookie OCTET STRING,
        } );
        bb.flip();

        PagedResultsFactory factory = ( PagedResultsFactory ) codec.getResponseControlFactories().get( PagedResults.OID );
        PagedResults pagedSearch = factory.newControl();
        factory.decodeValue( pagedSearch, bb.array() );
    }


    /**
     * Test the decoding of a PagedSearchControl with no size  and no cookie
     */
    @Test(expected = DecoderException.class)
    public void testDecodePagedSearchRequestNoSizeNoCookie() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );
        bb.put( new byte[]
            {
                0x30, 0x00, // realSearchControlValue ::= SEQUENCE
            } );
        bb.flip();

        PagedResultsFactory factory = ( PagedResultsFactory ) codec.getResponseControlFactories().get( PagedResults.OID );
        PagedResults pagedSearch = factory.newControl();
        factory.decodeValue( pagedSearch, bb.array() );
    }


    /**
     * Test encoding of a PagedSearchControl with a negative size
     */
    @Test
    public void testEncodePagedSearchControlNegativeSize() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0b );
        bb.put( new byte[]
            {
                0x30, 0x09,                     // realSearchControlValue ::= SEQUENCE {
                  0x02, 0x01, ( byte ) 0xFF,    // size INTEGER,
                  0x04, 0x04,
                    't', 'e', 's', 't'          // cookie OCTET STRING,
        } );
        bb.flip();

        PagedResultsFactory factory = ( PagedResultsFactory ) codec.getResponseControlFactories().get( PagedResults.OID );
        PagedResults pagedSearch = factory.newControl();
        factory.decodeValue( pagedSearch, bb.array() );

        assertEquals( Integer.MAX_VALUE, pagedSearch.getSize() );
        assertTrue( Arrays.equals( Strings.getBytesUtf8( "test" ),
            pagedSearch.getCookie() ) );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, pagedSearch );

        assertArrayEquals( 
            new byte[]
                {
                    0x30, 0x0C,
                      0x02, 0x04, 
                        0x7F, ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xFF,
                      0x04, 0x04,
                        0x74, 0x65, 0x73, 0x74
                },  asn1Buffer.getBytes().array() );
    }


    /**
     * Test encoding of a PagedSearchControl with a empty size
     */
    @Test(expected = DecoderException.class)
    public void testEncodePagedSearchControlEmptySize() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0a );
        bb.put( new byte[]
            {
                0x30, 0x08,                 // realSearchControlValue ::= SEQUENCE {
                  0x02, 0x00,               // size INTEGER,
                  0x04, 0x04,
                    't', 'e', 's', 't'      // cookie OCTET STRING,
        } );
        bb.flip();

        PagedResultsFactory factory = ( PagedResultsFactory ) codec.getResponseControlFactories().get( PagedResults.OID );
        PagedResults pagedSearch = factory.newControl();
        factory.decodeValue( pagedSearch, bb.array() );
    }


    /**
     * Test encoding of a PagedSearchControl with a empty cookie
     */
    @Test
    public void testEncodePagedSearchControlEmptyCookie() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x07 );
        bb.put( new byte[]
            {
                0x30, 0x05,                 // realSearchControlValue ::= SEQUENCE {
                  0x02, 0x01, 0x20,         // size INTEGER,
                  0x04, 0x00                // cookie OCTET STRING,
        } );
        bb.flip();

        PagedResultsFactory factory = ( PagedResultsFactory ) codec.getResponseControlFactories().get( PagedResults.OID );
        PagedResults pagedSearch = factory.newControl();
        factory.decodeValue( pagedSearch, bb.array() );

        assertEquals( 32, pagedSearch.getSize() );
        assertArrayEquals( Strings.EMPTY_BYTES, pagedSearch.getCookie() );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, pagedSearch );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }
}