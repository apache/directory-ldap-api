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


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.SearchResultReference;
import org.apache.directory.api.ldap.model.message.controls.EntryChange;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the SearchResultReference codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class SearchResultReferenceTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a SearchResultReference
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeSearchResultReferenceSuccess() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x3d8 );

        String[] ldapUrls = new String[]
            {
                "ldap:///", "ldap://directory.apache.org:80/", "ldap://d-a.org:80/", "ldap://1.2.3.4/",
                "ldap://1.2.3.4:80/", "ldap://1.1.1.100000.a/", "ldap://directory.apache.org:389/dc=example,dc=org/",
                "ldap://directory.apache.org:389/dc=example", "ldap://directory.apache.org:389/dc=example%202,dc=org",
                "ldap://directory.apache.org:389/dc=example,dc=org?ou",
                "ldap://directory.apache.org:389/dc=example,dc=org?ou,objectclass,dc",
                "ldap://directory.apache.org:389/dc=example,dc=org?ou,dc,ou",
                "ldap:///o=University%20of%20Michigan,c=US",
                "ldap://ldap.itd.umich.edu/o=University%20of%20Michigan,c=US",
                "ldap://ldap.itd.umich.edu/o=University%20of%20Michigan,c=US?postalAddress",
                "ldap://host.com:6666/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)",
                "ldap://ldap.itd.umich.edu/c=GB?objectClass?one", "ldap://ldap.question.com/o=Question%3f,c=US?mail",
                "ldap://ldap.netscape.com/o=Babsco,c=US???(int=%5c00%5c00%5c00%5c04)",
                "ldap:///??sub??bindname=cn=Manager%2co=Foo", "ldap:///??sub??!bindname=cn=Manager%2co=Foo"
            };

        stream.put( new byte[]
            {
                0x30, ( byte ) 0x82, 0x03, ( byte ) 0xd4,   // LDAPMessage SEQUENCE {
                  0x02, 0x01, 0x01,                         // messageID MessageID
                  0x73, ( byte ) 0x82, 0x03, ( byte ) 0xcd, // CHOICE { ...,
                                                            // searchResEntry
                                                            // SearchResultEntry,
                                                            // ...
                                                            // SearchResultReference ::= [APPLICATION 19] SEQUENCE OF LDAPURL
        } );

        for ( int i = 0; i < ldapUrls.length; i++ )
        {
            stream.put( ( byte ) 0x04 );
            stream.put( ( byte ) Strings.getBytesUtf8( ldapUrls[i] ).length );

            byte[] bytes = Strings.getBytesUtf8( ldapUrls[i] );

            for ( int j = 0; j < bytes.length; j++ )
            {
                stream.put( bytes[j] );
            }
        }

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultReference> ldapMessageContainer = 
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchResultReference searchResultReference = ldapMessageContainer.getMessage();

        assertEquals( 1, searchResultReference.getMessageId() );

        Set<String> ldapUrlsSet = new HashSet<String>();

        for ( int i = 0; i < ldapUrls.length; i++ )
        {
            ldapUrlsSet.add( ldapUrls[i] );
        }

        Referral referral = searchResultReference.getReferral();

        assertNotNull( referral );

        for ( String ldapUrl : referral.getLdapUrls() )
        {
            if ( ldapUrlsSet.contains( ldapUrl ) )
            {
                ldapUrlsSet.remove( ldapUrl );
            }
            else
            {
                fail( ldapUrl.toString() + " is not present" );
            }
        }

        assertTrue( ldapUrlsSet.size() == 0 );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchResultReference );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchResultReference with controls
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeSearchResultReferenceSuccessWithControls() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x3FC );

        String[] ldapUrls = new String[]
            {
                "ldap:///", "ldap://directory.apache.org:80/", "ldap://d-a.org:80/", "ldap://1.2.3.4/",
                "ldap://1.2.3.4:80/", "ldap://1.1.1.100000.a/", "ldap://directory.apache.org:389/dc=example,dc=org/",
                "ldap://directory.apache.org:389/dc=example", "ldap://directory.apache.org:389/dc=example%202,dc=org",
                "ldap://directory.apache.org:389/dc=example,dc=org?ou",
                "ldap://directory.apache.org:389/dc=example,dc=org?ou,objectclass,dc",
                "ldap://directory.apache.org:389/dc=example,dc=org?ou,dc,ou",
                "ldap:///o=University%20of%20Michigan,c=US",
                "ldap://ldap.itd.umich.edu/o=University%20of%20Michigan,c=US",
                "ldap://ldap.itd.umich.edu/o=University%20of%20Michigan,c=US?postalAddress",
                "ldap://host.com:6666/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)",
                "ldap://ldap.itd.umich.edu/c=GB?objectClass?one", "ldap://ldap.question.com/o=Question%3f,c=US?mail",
                "ldap://ldap.netscape.com/o=Babsco,c=US???(int=%5c00%5c00%5c00%5c04)",
                "ldap:///??sub??bindname=cn=Manager%2co=Foo", "ldap:///??sub??!bindname=cn=Manager%2co=Foo"
            };

        stream.put( new byte[]
            {

                0x30, ( byte ) 0x82, 0x03, ( byte ) 0xF8,   // LDAPMessage
                  0x02, 0x01, 0x01,                         // messageID MessageID
                  0x73, ( byte ) 0x82, 0x03, ( byte ) 0xcd, // CHOICE { ...,
                                                            // searchResEntry
                                                            // SearchResultEntry,
                                                            // ...
                                                            // SearchResultReference ::= [APPLICATION 19] SEQUENCE OF LDAPURL
        } );

        for ( int i = 0; i < ldapUrls.length; i++ )
        {
            stream.put( ( byte ) 0x04 );
            stream.put( ( byte ) Strings.getBytesUtf8( ldapUrls[i] ).length );

            byte[] bytes = Strings.getBytesUtf8( ldapUrls[i] );

            for ( int j = 0; j < bytes.length; j++ )
            {
                stream.put( bytes[j] );
            }
        }

        byte[] controlBytes = new byte[]
            {
                ( byte ) 0xA0, 0x22,          // A control
                  0x30, 0x20,
                    0x04, 0x17,               // EntryChange response control
                      '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.', 
                      '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '7',
                    0x04, 0x05,               // Control value
                      0x30, 0x03,             // EntryChangeNotification ::= SEQUENCE {
                        0x0A, 0x01, 0x01      //     changeType ENUMERATED {
                                              //         add             (1),
            };

        for ( int i = 0; i < controlBytes.length; i++ )
        {
            stream.put( controlBytes[i] );
        }

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultReference> ldapMessageContainer = 
            new LdapMessageContainer<>( codec );

        ldapMessageContainer.clean();
        Asn1Decoder.decode( stream, ldapMessageContainer );

        stream.flip();

        SearchResultReference searchResultReference = ldapMessageContainer.getMessage();

        assertEquals( 1, searchResultReference.getMessageId() );

        Set<String> ldapUrlsSet = new HashSet<String>();

        for ( int i = 0; i < ldapUrls.length; i++ )
        {
            ldapUrlsSet.add( ldapUrls[i] );
        }

        Referral referral = searchResultReference.getReferral();

        assertNotNull( referral );

        for ( String ldapUrl : referral.getLdapUrls() )
        {
            if ( ldapUrlsSet.contains( ldapUrl ) )
            {
                ldapUrlsSet.remove( ldapUrl );
            }
            else
            {
                fail( ldapUrl.toString() + " is not present" );
            }
        }

        assertTrue( ldapUrlsSet.size() == 0 );

        // Check the Control
        Map<String, Control> controls = searchResultReference.getControls();

        assertEquals( 1, controls.size() );

        Control control = controls.get( "2.16.840.1.113730.3.4.7" );
        assertEquals( "2.16.840.1.113730.3.4.7", control.getOid() );
        assertTrue ( control instanceof EntryChange );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchResultReference );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchResultReference with no reference
     */
    @Test
    public void testDecodeSearchResultReferenceNoReference()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            {
                0x30, 0x05,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x73, 0x00                // CHOICE { ..., searchResEntry SearchResultEntry,
                                            // ...
                                            // SearchResultReference ::= [APPLICATION 19] SEQUENCE OF LDAPURL
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchResultReference> ldapMessageContainer = 
            new LdapMessageContainer<>( codec );

        // Decode a SearchResultReference message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchResultReference with one reference
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeSearchResultReferenceOneReference() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x11 );

        stream.put( new byte[]
            {
                0x30, 0x0F,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x73, 0x0A,               // CHOICE { ..., searchResEntry SearchResultEntry,
                                            // ...
                    0x04, 0x08,             // SearchResultReference
                      'l', 'd', 'a', 'p', ':', '/', '/', '/'
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultReference> ldapMessageContainer = 
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchResultReference searchResultReference = ldapMessageContainer.getMessage();

        assertEquals( 1, searchResultReference.getMessageId() );

        Referral referral = searchResultReference.getReferral();

        assertNotNull( referral );

        for ( String ldapUrl : referral.getLdapUrls() )
        {
            assertEquals( "ldap:///", ldapUrl );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchResultReference );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }
}
