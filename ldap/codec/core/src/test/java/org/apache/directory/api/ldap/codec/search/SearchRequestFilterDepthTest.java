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
package org.apache.directory.api.ldap.codec.search;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.TLVStateEnum;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests that the depth of a SearchRequest filter, which is fully driven by
 * the incoming PDU, is bounded : a deeply nested filter must be rejected with
 * a DecoderException instead of triggering a StackOverflowError.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class SearchRequestFilterDepthTest extends AbstractCodecServiceTest
{
    /**
     * Encode one TLV with a definite length
     */
    private static byte[] computeTlv( int tag, byte[] value ) throws IOException
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write( tag );

        int length = value.length;
        
        out.write( TLV.getBytes( length ) );
        out.write( value );

        return out.toByteArray();
    }


    /**
     * Build a valid SearchRequest PDU whose filter is <code>depth</code>
     * nested NOT filters around a present filter.
     */
    private static ByteBuffer buildSearchRequestWithNotDepth( int depth ) throws IOException
    {
        // recursively create the filter, starting with the inner most
        byte[] filter = computeTlv( 
            (byte)0x87, // present [7] AttributeDescription
            new byte[] 
            {
                'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's' // The ObjectClass attribute
            } );

        // Wrap it in <depth> NOT filters
        for ( int i = 0; i < depth; i++ )
        {
            filter = computeTlv( 0xA2, filter );
        }

        ByteArrayOutputStream searchRequest = new ByteArrayOutputStream();
        searchRequest.write( new byte[] { 0x04, 0x00 } );       // baseObject : rootDSE
        searchRequest.write( new byte[] { 0x0A, 0x01, 0x00 } ); // scope : baseObject
        searchRequest.write( new byte[] { 0x0A, 0x01, 0x00 } ); // derefAliases : never
        searchRequest.write( new byte[] { 0x02, 0x01, 0x00 } ); // sizeLimit : 0
        searchRequest.write( new byte[] { 0x02, 0x01, 0x00 } ); // timeLimit : 0
        searchRequest.write( new byte[] { 0x01, 0x01, 0x00 } ); // typesOnly : false
        searchRequest.write( filter );                          // filter
        searchRequest.write( new byte[] { 0x30, 0x00 } );       // attributes : none

        ByteArrayOutputStream message = new ByteArrayOutputStream();
        message.write( new byte[] { 0x02, 0x01, 0x01 } );       // messageID : 1
        message.write( computeTlv( 0x63, searchRequest.toByteArray() ) );

        byte[] pdu = computeTlv( 0x30, message.toByteArray() );

        ByteBuffer stream = ByteBuffer.allocate( pdu.length );
        stream.put( pdu );
        stream.flip();

        return stream;
    }


    /**
     * A filter nested deeper than the default limit must be rejected with a
     * DecoderException, not a StackOverflowError.
     */
    @Test
    public void testDeeplyNestedFilterIsRejected() throws IOException
    {
        ByteBuffer stream = buildSearchRequestWithNotDepth(
            LdapMessageContainer.DEFAULT_MAX_FILTER_DEPTH + 10 );

        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        assertThrows( DecoderException.class, () -> Asn1Decoder.decode( stream, ldapMessageContainer ) );
    }


    /**
     * A reasonably nested filter must still decode fine.
     */
    @Test
    public void testReasonablyNestedFilterIsAccepted() throws Exception
    {
        ByteBuffer stream = buildSearchRequestWithNotDepth( 10 );

        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );
    }
}
