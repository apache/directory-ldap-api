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


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncDone.SyncDoneValue;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncState.SyncStateTypeEnum;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncState.SyncStateValue;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncDoneValueFactory;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncStateValueFactory;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionResponse;
import org.apache.directory.api.ldap.extras.extended.endTransaction.UpdateControls;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.SortResponse;
import org.apache.directory.api.ldap.model.message.controls.SortResultCode;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the EndTransactionResponse codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class EndTransactionResponseTest extends AbstractCodecServiceTest
{
    static
    {
        LdapApiServiceFactory.initialize( codec );
    }
    
    @BeforeEach
    public void init()
    {
        codec = LdapApiServiceFactory.getSingleton();
        codec.registerResponseControl( new SyncDoneValueFactory( codec ) );
        codec.registerResponseControl( new SyncStateValueFactory( codec ) );
        codec.registerExtendedResponse( new EndTransactionFactory( codec ) );
    }
    
    
    /**
     * Test the decoding of a EndTransactionResponse with nothing in it
     */
    @Test
    public void testDecodeEndTransactionResponseEmpty() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x00, // EndTransactionResponse ::= SEQUENCE {
            };

        EndTransactionFactory factory = ( EndTransactionFactory ) codec.getExtendedResponseFactories().
            get( EndTransactionResponse.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( bb );
        } );
    }


    /**
     * Test the decoding of a EndTransactionResponse with a messageId and no updateControls
     */
    @Test
    public void testEndTransactionResponseMessageId() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x03,              // EndTransactionResponse ::= SEQUENCE {
                  0x02, 0x01, 0x04       // MessageId
            };

        EndTransactionFactory factory = ( EndTransactionFactory ) codec.getExtendedResponseFactories().
            get( EndTransactionResponse.EXTENSION_OID );
        EndTransactionResponse endTransactionResponse = ( EndTransactionResponse ) factory.newResponse( bb );

        assertEquals( 4, endTransactionResponse.getFailedMessageId() );
        assertEquals( 0, endTransactionResponse.getUpdateControls().size() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, endTransactionResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a EndTransactionResponse with updateControls
     */
    @Test
    public void testEndTransactionResponseUpdateControls() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, (byte)0x82, 0x01, 0x29,         // EndTransactionResponse ::= SEQUENCE {
                  0x30, (byte)0x82, 0x01, 0x25,       // UpdateControls
                    0x30, (byte)0x81, (byte)0xA5,     // updateControl
                      0x02, 0x01, 0x01,               // messageID
                      0x30, (byte)0x81, (byte)0x9F,   // controls 
                        0x30, 0x26,                   // Control ::= SEQUENCE {
                          0x04, 0x16,                 // controlType LDAPOID,
                                                      // PagedResults
                            '1', '.', '2', '.', '8', '4', '0', '.', 
                            '1', '1', '3', '5', '5', '6', '.', '1', '.', '4', '.', '3', '1', '9',
                          0x01, 0x01, ( byte ) 0xFF,  // criticality BOOLEAN DEFAULT FALSE, 
                          0x04, 0x09,                 // controlValue OCTET STRING OPTIONAL }
                            0x30, 0x07,
                              0x02, 0x01, 0x01,
                              0x04, 0x02,
                                'a', 'b',
                        0x30, 0x23,                   // Control ::= SEQUENCE {
                          0x04, 0x16,                 // controlType LDAPOID,
                                                      // SortResponse
                            '1', '.', '2', '.', '8', '4', '0', '.', 
                            '1', '1', '3', '5', '5', '6', '.', '1', '.', '4', '.', '4', '7', '4',
                          0x04, 0x09,                 // controlValue OCTET STRING OPTIONAL }
                            0x30, 0x07,
                              0x0A, 0x01, 0x08,
                              (byte)0x80, 0x02,
                                'c', 'n',
                        0x30, 0x27,                   // Control ::= SEQUENCE {
                          0x04, 0x18,                 // controlType LDAPOID,
                                                      // SyncDoneValue
                            '1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.', 
                            '4', '2', '0', '3', '.', '1', '.', '9', '.', '1', '.', '3',
                          0x01, 0x01, ( byte ) 0xFF,  // criticality BOOLEAN DEFAULT FALSE}
                          0x04, 0x08,
                            0x30, 0x06,
                              0x04, 0x04,
                               't', 't', 't', 't',
                        0x30, 0x27,                   // Control ::= SEQUENCE {
                          0x04, 0x18,                 // controlType LDAPOID}
                                                      // SyncStateValue
                            '1', '.', '3', '.', '6', '.', '1', '.', '4', '.', 
                            '1', '.', '4', '2', '0', '3', '.', '1', '.', '9', '.', '1', '.', '2',
                          0x04, 0x0B,                 // ControlValue  OCTET STRING OPTIONAL }
                            0x30, 0x09,
                              0x0A, 0x01, 0x01,       // Add
                              0x04, 0x04,
                                'a', 'b', 'c', 'd',   // EntryUUID
                    0x30, 0x7B,                       // updateControl
                      0x02, 0x01, 0x02,               // messageID
                      0x30, 0x76,                     // controls 
                        0x30, 0x26,                   // Control ::= SEQUENCE {
                          0x04, 0x16,                 // controlType LDAPOID,
                                                      // PagedResults
                            '1', '.', '2', '.', '8', '4', '0', '.', 
                            '1', '1', '3', '5', '5', '6', '.', '1', '.', '4', '.', '3', '1', '9',
                          0x01, 0x01, ( byte ) 0xFF,  // criticality BOOLEAN DEFAULT FALSE, 
                          0x04, 0x09,                 // controlValue OCTET STRING OPTIONAL }
                            0x30, 0x07,
                              0x02, 0x01, 0x01,
                              0x04, 0x02,
                                'a', 'b',
                        0x30, 0x23,                   // Control ::= SEQUENCE {
                          0x04, 0x16,                 // controlType LDAPOID,
                                                      // SortResponse
                            '1', '.', '2', '.', '8', '4', '0', '.', 
                            '1', '1', '3', '5', '5', '6', '.', '1', '.', '4', '.', '4', '7', '4',
                          0x04, 0x09,                 // controlValue OCTET STRING OPTIONAL }
                            0x30, 0x07,
                              0x0A, 0x01, 0x08,
                              (byte)0x80, 0x02,
                                'c', 'n',
                        0x30, 0x27,                   // Control ::= SEQUENCE {
                          0x04, 0x18,                 // controlType LDAPOID,
                                                      // SyncDoneValue
                            '1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.', 
                            '4', '2', '0', '3', '.', '1', '.', '9', '.', '1', '.', '3',
                          0x01, 0x01, ( byte ) 0xFF,  // criticality BOOLEAN DEFAULT FALSE}
                          0x04, 0x08,
                            0x30, 0x06,
                              0x04, 0x04,
                               't', 't', 't', 't',
        };
        
        EndTransactionFactory factory = ( EndTransactionFactory ) codec.getExtendedResponseFactories().
            get( EndTransactionResponse.EXTENSION_OID );
        EndTransactionResponse endTransactionResponse = ( EndTransactionResponse ) factory.newResponse( bb );

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
                case "1.2.840.113556.1.4.319" :
                    assertTrue( control.isCritical() );
                    assertTrue( control instanceof PagedResults );
                    PagedResults pagedResults = ( PagedResults ) control;
                    assertEquals( 1, pagedResults.getSize() );
                    assertEquals( "ab", Strings.utf8ToString( pagedResults.getCookie() ) );
                    break;
                    
                case "1.2.840.113556.1.4.474" :
                    assertFalse( control.isCritical() );
                    assertTrue( control instanceof SortResponse );
                    SortResponse sortResponse = ( SortResponse ) control;
                    assertEquals( SortResultCode.STRONGAUTHREQUIRED, sortResponse.getSortResult() );
                    assertEquals( "cn", sortResponse.getAttributeName() );
                    break;
                    
                case "1.3.6.1.4.1.4203.1.9.1.3" :
                    assertTrue( control.isCritical() );
                    assertTrue( control instanceof SyncDoneValue );
                    SyncDoneValue syncDoneValue = ( SyncDoneValue ) control;
                    assertEquals( "tttt", Strings.utf8ToString( syncDoneValue.getCookie() ) );
                    break;
                    
                case "1.3.6.1.4.1.4203.1.9.1.2" :
                    assertFalse( control.isCritical() );
                    assertTrue( control instanceof SyncStateValue );
                    SyncStateValue syncStateValue = ( SyncStateValue ) control;
                    assertEquals( SyncStateTypeEnum.ADD, syncStateValue.getSyncStateType() );
                    assertEquals( "abcd", Strings.utf8ToString( syncStateValue.getEntryUUID() ) );
                    assertNull( syncStateValue.getCookie() );
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
                case "1.2.840.113556.1.4.319" :
                    assertTrue( control.isCritical() );
                    assertTrue( control instanceof PagedResults );
                    PagedResults pagedResults = ( PagedResults ) control;
                    assertEquals( 1, pagedResults.getSize() );
                    assertEquals( "ab", Strings.utf8ToString( pagedResults.getCookie() ) );
                    break;
                    
                case "1.2.840.113556.1.4.474" :
                    assertFalse( control.isCritical() );
                    assertTrue( control instanceof SortResponse );
                    SortResponse sortResponse = ( SortResponse ) control;
                    assertEquals( SortResultCode.STRONGAUTHREQUIRED, sortResponse.getSortResult() );
                    assertEquals( "cn", sortResponse.getAttributeName() );
                    break;
                    
                case "1.3.6.1.4.1.4203.1.9.1.3" :
                    assertTrue( control.isCritical() );
                    SyncDoneValue syncDoneValue = ( SyncDoneValue ) control;
                    assertEquals( "tttt", Strings.utf8ToString( syncDoneValue.getCookie() ) );
                    break;
                    
                default :
                    fail();
                    break;
            }
        }

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, endTransactionResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }
}
