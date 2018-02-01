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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionResponse;
import org.apache.directory.api.ldap.extras.extended.endTransaction.UpdateControls;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the EndTransactionResponse codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class EndTransactionResponseTest
{
    /**
     * Test the decoding of a EndTransactionResponse with nothing in it
     */
    @Test( expected=DecoderException.class)
    public void testDecodeEndTransactionResponseEmpty() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );
        bb.put( new byte[]
            { 0x30, 0x00, // EndTransactionResponse ::= SEQUENCE {
            } );
        
        bb.flip();

        EndTransactionResponseContainer container = new EndTransactionResponseContainer();

        decoder.decode( bb, container );
    }


    /**
     * Test the decoding of a EndTransactionResponse with a messageId and no updateControls
     */
    @Test
    public void testEndTransactionResponseMessageId() throws DecoderException, EncoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x05 );
        bb.put( new byte[]
            { 0x30, 0x03,              // EndTransactionResponse ::= SEQUENCE {
                0x02, 0x01, 0x04       // MessageId
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();
        EndTransactionResponseContainer container = new EndTransactionResponseContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }
        
        EndTransactionResponse endTransactionResponse = container.getEndTransactionResponse();
        assertEquals( 4, endTransactionResponse.getFailedMessageId() );
        assertEquals( 0, endTransactionResponse.getUpdateControls().size() );

        // Check the length
        assertEquals( 0x05, ( ( EndTransactionResponseDecorator ) endTransactionResponse ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( EndTransactionResponseDecorator ) endTransactionResponse ).encodeInternal();

        String encodedPdu = Strings.dumpBytes( bb1.array() );

        assertEquals( encodedPdu, decodedPdu );
    }


    /**
     * Test the decoding of a EndTransactionResponse with updateControls
     */
    @Test
    public void testEndTransactionResponseUpdateControls() throws DecoderException, EncoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0xAC );
        bb.put( new byte[]
            { 0x30, (byte)0x81, (byte)0xA9,         // EndTransactionResponse ::= SEQUENCE {
                0x30, (byte)0x81, (byte)0xA6,       // UpdateControls
                  0x30, 0x5F,                       // updateControl
                    0x02, 0x01, 0x01,               // messageID
                    0x30, 0x5A,                     // controls 
                      0x30, 0x1A,                   // Control ::= SEQUENCE {
                        0x04, 0x0D,                 // controlType LDAPOID,
                          '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '1',
                        0x01, 0x01, ( byte ) 0xFF,  // criticality BOOLEAN DEFAULT FALSE, 
                        0x04, 0x06,                 // controlValue OCTET STRING OPTIONAL }
                          'a', 'b', 'c', 'd', 'e', 'f',
                      0x30, 0x17,                   // Control ::= SEQUENCE {
                        0x04, 0x0D,                 // controlType LDAPOID,
                          '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2',
                        0x04, 0x06,                 // controlValue OCTET STRING OPTIONAL }
                          'g', 'h', 'i', 'j', 'k', 'l',
                      0x30, 0x12,                   // Control ::= SEQUENCE {
                        0x04, 0x0D,                 // controlType LDAPOID,
                          '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '3',
                        0x01, 0x01, ( byte ) 0xFF,  // criticality BOOLEAN DEFAULT FALSE}
                      0x30, 0x0F,                   // Control ::= SEQUENCE {
                        0x04, 0x0D,                 // controlType LDAPOID}
                          '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '4',
                  0x30, 0x43,                       // updateControl
                    0x02, 0x01, 0x02,               // messageID
                    0x30, 0x3E,                     // controls 
                      0x30, 0x17,                   // Control ::= SEQUENCE {
                        0x04, 0x0D,                 // controlType LDAPOID,
                          '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2',
                        0x04, 0x06,                 // controlValue OCTET STRING OPTIONAL }
                          'g', 'h', 'i', 'j', 'k', 'l',
                      0x30, 0x12,                   // Control ::= SEQUENCE {
                        0x04, 0x0D,                 // controlType LDAPOID,
                          '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '3',
                        0x01, 0x01, ( byte ) 0xFF,  // criticality BOOLEAN DEFAULT FALSE}
                      0x30, 0x0F,                   // Control ::= SEQUENCE {
                        0x04, 0x0D,                 // controlType LDAPOID}
                          '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '4' 

        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();
        EndTransactionResponseContainer container = new EndTransactionResponseContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }
        
        EndTransactionResponse endTransactionResponse = container.getEndTransactionResponse();
        assertEquals( -1, endTransactionResponse.getFailedMessageId() );
        assertEquals( 2, endTransactionResponse.getUpdateControls().size() );
        
        UpdateControls updateControls1 = endTransactionResponse.getUpdateControls().get( 0 );
        assertEquals( 1, updateControls1.getMessageId() );
        assertNotNull( updateControls1.getControls() );
        assertEquals( 4, updateControls1.getControls().size() );
        
        for ( Control control : updateControls1.getControls() )
        {
            switch ( control.getOid() )
            {
                case "1.3.6.1.5.5.1" :
                    assertTrue( control.isCritical() );
                    assertEquals( "abcdef", Strings.utf8ToString( ( ( CodecControl<?> ) control ).getValue() ) );
                    break;
                    
                case "1.3.6.1.5.5.2" :
                    assertFalse( control.isCritical() );
                    assertEquals( "ghijkl", Strings.utf8ToString( ( ( CodecControl<?> ) control ).getValue() ) );
                    break;
                    
                case "1.3.6.1.5.5.3" :
                    assertTrue( control.isCritical() );
                    assertNull( ( ( CodecControl<?> ) control ).getValue() );
                    break;
                    
                case "1.3.6.1.5.5.4" :
                    assertFalse( control.isCritical() );
                    assertNull( ( ( CodecControl<?> ) control ).getValue() );
                    break;
                    
                default :
                    fail();
                    break;
            }
        }

        UpdateControls updateControls2 = endTransactionResponse.getUpdateControls().get( 1 );
        assertEquals( 2, updateControls2.getMessageId() );
        assertNotNull( updateControls2.getControls() );
        assertEquals( 3, updateControls2.getControls().size() );
        
        for ( Control control : updateControls2.getControls() )
        {
            switch ( control.getOid() )
            {
                case "1.3.6.1.5.5.2" :
                    assertFalse( control.isCritical() );
                    assertEquals( "ghijkl", Strings.utf8ToString( ( ( CodecControl<?> ) control ).getValue() ) );
                    break;
                    
                case "1.3.6.1.5.5.3" :
                    assertTrue( control.isCritical() );
                    assertNull( ( ( CodecControl<?> ) control ).getValue() );
                    break;
                    
                case "1.3.6.1.5.5.4" :
                    assertFalse( control.isCritical() );
                    assertNull( ( ( CodecControl<?> ) control ).getValue() );
                    break;
                    
                default :
                    fail();
                    break;
            }
        }

        // Check the length
        assertEquals( 0xAC, ( ( EndTransactionResponseDecorator ) endTransactionResponse ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( EndTransactionResponseDecorator ) endTransactionResponse ).encodeInternal();

        String encodedPdu = Strings.dumpBytes( bb1.array() );

        assertEquals( encodedPdu, decodedPdu );
    }
}
