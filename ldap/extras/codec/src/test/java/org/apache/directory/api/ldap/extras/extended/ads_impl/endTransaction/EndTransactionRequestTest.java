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
package org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionRequest;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the EndTransactionRequest codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class EndTransactionRequestTest
{
    private static LdapApiService codec;

    @BeforeAll
    public static void init()
    {
        codec = new DefaultLdapCodecService();
        codec.registerExtendedRequest( new EndTransactionFactory( codec ) );
    }
    
    
    /**
     * Test the decoding of a EndTransactionRequest with nothing in it
     */
    @Test
    public void testDecodeEndTransactionRequestEmpty() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x00, // EndTransactionRequest ::= SEQUENCE {
            };
        
        EndTransactionFactory factory = ( EndTransactionFactory ) codec.getExtendedRequestFactories().
            get( EndTransactionRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( bb );
        } );
    }


    /**
     * Test the decoding of a EndTransactionRequest with an commit but no identifier
     */
    @Test
    public void testEndTransactionRequestCommitNoIdentifier() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x03,              // EndTransactionRequest ::= SEQUENCE {
                  0x01, 0x01, 0x00       // Commit, TRUE
            };

        EndTransactionFactory factory = ( EndTransactionFactory ) codec.getExtendedRequestFactories().
            get( EndTransactionRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( bb );
        } );
    }


    /**
     * Test the decoding of a EndTransactionRequest with an identifier but no commit
     * @throws EncoderException 
     */
    @Test
    public void testEndTransactionRequestNoCommitIdentifier() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x06,                       // EndTransactionRequest ::= SEQUENCE {
                  0x04, 0x04, 't', 'e', 's', 't'  // identifier (test)
            };

        EndTransactionFactory factory = ( EndTransactionFactory ) codec.getExtendedRequestFactories().
            get( EndTransactionRequest.EXTENSION_OID );
        EndTransactionRequest endTransactionRequest = ( EndTransactionRequest ) factory.newRequest( bb );

        assertTrue( endTransactionRequest.getCommit() );
        assertEquals( "test", Strings.utf8ToString( endTransactionRequest.getTransactionId() ) );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, endTransactionRequest );
        
        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a EndTransactionRequest with an identifier and a commit
     * @throws EncoderException 
     */
    @Test
    public void testEndTransactionRequesoCommitIdentifier() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x09,                       // EndTransactionRequest ::= SEQUENCE {
                  0x01, 0x01, 0x00,               // Commit, FALSE
                  0x04, 0x04, 't', 'e', 's', 't'  // identifier (test)
            };

        EndTransactionFactory factory = ( EndTransactionFactory ) codec.getExtendedRequestFactories().
            get( EndTransactionRequest.EXTENSION_OID );
        EndTransactionRequest endTransactionRequest = ( EndTransactionRequest ) factory.newRequest( bb );

        assertFalse( endTransactionRequest.getCommit() );
        assertEquals( "test", Strings.utf8ToString( endTransactionRequest.getTransactionId() ) );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, endTransactionRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a EndTransactionRequest with an empty identifier and a commit
     * @throws EncoderException 
     */
    @Test
    public void testEndTransactionRequesoCommitEmptyIdentifier() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x05,                       // EndTransactionRequest ::= SEQUENCE {
                  0x01, 0x01, 0x00,               // Commit, FALSE
                  0x04, 0x00                      // identifier (empty)
            };

        EndTransactionFactory factory = ( EndTransactionFactory ) codec.getExtendedRequestFactories().
            get( EndTransactionRequest.EXTENSION_OID );
        EndTransactionRequest endTransactionRequest = ( EndTransactionRequest ) factory.newRequest( bb );

        assertFalse( endTransactionRequest.getCommit() );
        assertEquals( 0, endTransactionRequest.getTransactionId().length );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, endTransactionRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }
}
