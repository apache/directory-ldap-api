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
package org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionRequest;
import org.apache.directory.api.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the EndTransactionRequest codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class EndTransactionRequestTest
{
    /**
     * Test the decoding of a EndTransactionRequest with nothing in it
     */
    @Test( expected=DecoderException.class)
    public void testDecodeEndTransactionRequestEmpty() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );
        bb.put( new byte[]
            { 0x30, 0x00, // EndTransactionRequest ::= SEQUENCE {
            } );
        
        bb.flip();

        EndTransactionRequestContainer container = new EndTransactionRequestContainer();

        decoder.decode( bb, container );
    }


    /**
     * Test the decoding of a EndTransactionRequest with an commit but no identifier
     */
    @Test( expected=DecoderException.class )
    public void testEndTransactionRequestCommitNoIdentifier() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x05 );
        bb.put( new byte[]
            { 0x30, 0x03,              // EndTransactionRequest ::= SEQUENCE {
                0x01, 0x01, 0x00       // Commit, TRUE
        } );

        bb.flip();

        EndTransactionRequestContainer container = new EndTransactionRequestContainer();

        decoder.decode( bb, container );
    }


    /**
     * Test the decoding of a EndTransactionRequest with an identifier but no commit
     * @throws EncoderException 
     */
    @Test
    public void testEndTransactionRequestNoCommitIdentifier() throws EncoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            { 0x30, 0x06,                       // EndTransactionRequest ::= SEQUENCE {
                0x04, 0x04, 't', 'e', 's', 't'  // identifier (test)
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        EndTransactionRequestContainer container = new EndTransactionRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }
        
        EndTransactionRequest endTransactionRequest = container.getEndTransactionRequest();
        assertTrue( endTransactionRequest.getCommit() );
        assertEquals( "test", Strings.utf8ToString( endTransactionRequest.getTransactionId() ) );

        // Check the length
        assertEquals( 0x08, ( ( EndTransactionRequestDecorator ) endTransactionRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( EndTransactionRequestDecorator ) endTransactionRequest ).encodeInternal();

        String encodedPdu = Strings.dumpBytes( bb1.array() );

        assertEquals( encodedPdu, decodedPdu );
    }


    /**
     * Test the decoding of a EndTransactionRequest with an identifier and a commit
     * @throws EncoderException 
     */
    @Test
    public void testEndTransactionRequesoCommitIdentifier() throws EncoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x0B );
        bb.put( new byte[]
            { 0x30, 0x09,                       // EndTransactionRequest ::= SEQUENCE {
                0x01, 0x01, 0x00,               // Commit, FALSE
                0x04, 0x04, 't', 'e', 's', 't'  // identifier (test)
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        EndTransactionRequestContainer container = new EndTransactionRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }
        
        EndTransactionRequest endTransactionRequest = container.getEndTransactionRequest();
        assertFalse( endTransactionRequest.getCommit() );
        assertEquals( "test", Strings.utf8ToString( endTransactionRequest.getTransactionId() ) );

        // Check the length
        assertEquals( 0x0B, ( ( EndTransactionRequestDecorator ) endTransactionRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( EndTransactionRequestDecorator ) endTransactionRequest ).encodeInternal();

        String encodedPdu = Strings.dumpBytes( bb1.array() );

        assertEquals( encodedPdu, decodedPdu );
    }


    /**
     * Test the decoding of a EndTransactionRequest with an empty identifier and a commit
     * @throws EncoderException 
     */
    @Test
    public void testEndTransactionRequesoCommitEmptyIdentifier() throws EncoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x07 );
        bb.put( new byte[]
            { 0x30, 0x05,                       // EndTransactionRequest ::= SEQUENCE {
                0x01, 0x01, 0x00,               // Commit, FALSE
                0x04, 0x00                      // identifier (empty)
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        EndTransactionRequestContainer container = new EndTransactionRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }
        
        EndTransactionRequest endTransactionRequest = container.getEndTransactionRequest();
        assertFalse( endTransactionRequest.getCommit() );
        assertEquals( 0, endTransactionRequest.getTransactionId().length );

        // Check the length
        assertEquals( 0x07, ( ( EndTransactionRequestDecorator ) endTransactionRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( EndTransactionRequestDecorator ) endTransactionRequest ).encodeInternal();

        String encodedPdu = Strings.dumpBytes( bb1.array() );

        assertEquals( encodedPdu, decodedPdu );
    }
}
