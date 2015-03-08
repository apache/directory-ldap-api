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

package org.apache.directory.api.ldap.extras.controls.vlv;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.controls.vlv_impl.VirtualListViewRequestDecorator;
import org.apache.directory.api.util.Strings;
import org.junit.Test;


/**
 * VLV control tests.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class VLVTest extends AbstractCodecServiceTest
{
    @Test
    public void testDecodeOffsetWithContextID() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x16 );

        bb.put( new byte[]
            {
                0x30, 0x14,
                0x02, 0x01, 0x01, // beforeCount
                0x02,
                0x01,
                0x01, // afterCount
                ( byte ) 0xA0,
                0x06,
                0x02, // offset
                0x01,
                0x01,
                0x02, // contentCount
                0x01,
                0x01,
                0x04, // ContextID
                0x04,
                'a',
                'b',
                'c',
                'd'
        } );

        bb.flip();

        VirtualListViewRequestDecorator control = new VirtualListViewRequestDecorator( codec );
        VirtualListViewRequest virtualListView = ( VirtualListViewRequest ) control.decode( bb.array() );

        assertEquals( 1, virtualListView.getBeforeCount() );
        assertEquals( 1, virtualListView.getAfterCount() );
        assertTrue( virtualListView.hasOffset() );
        assertEquals( 1, virtualListView.getOffset() );
        assertEquals( 1, virtualListView.getContentCount() );
        assertEquals( "abcd", Strings.utf8ToString( virtualListView.getContextId() ) );

        ByteBuffer encoded = ( ( VirtualListViewRequestDecorator ) virtualListView ).encode(
            ByteBuffer.allocate( ( ( VirtualListViewRequestDecorator ) virtualListView ).computeLength() ) );
        assertEquals( Strings.dumpBytes( bb.array() ), Strings.dumpBytes( encoded.array() ) );
    }


    @Test
    public void testDecodeOffsetWithoutContextID() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x10 );

        bb.put( new byte[]
            {
                0x30, 0x0E,
                0x02, 0x01, 0x01, // beforeCount
                0x02,
                0x01,
                0x01, // afterCount
                ( byte ) 0xA0,
                0x06,
                0x02, // offset
                0x01,
                0x01,
                0x02, // ContentCount
                0x01,
                0x01
        } );

        bb.flip();

        VirtualListViewRequestDecorator control = new VirtualListViewRequestDecorator( codec );
        VirtualListViewRequest virtualListView = ( VirtualListViewRequest ) control.decode( bb.array() );

        assertEquals( 1, virtualListView.getBeforeCount() );
        assertEquals( 1, virtualListView.getAfterCount() );
        assertTrue( virtualListView.hasOffset() );
        assertEquals( 1, virtualListView.getOffset() );
        assertEquals( 1, virtualListView.getContentCount() );
        assertNull( virtualListView.getContextId() );

        ByteBuffer encoded = ( ( VirtualListViewRequestDecorator ) virtualListView ).encode(
            ByteBuffer.allocate( ( ( VirtualListViewRequestDecorator ) virtualListView ).computeLength() ) );
        assertEquals( Strings.dumpBytes( bb.array() ), Strings.dumpBytes( encoded.array() ) );
    }


    @Test
    public void testDecodeOffsetEmptyContextID() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x12 );

        bb.put( new byte[]
            {
                0x30, 0x10,
                0x02, 0x01, 0x01, // beforeCount
                0x02,
                0x01,
                0x01, // afterCount
                ( byte ) 0xA0,
                0x06,
                0x02, // offset
                0x01,
                0x01,
                0x02, // ContentCount
                0x01,
                0x01,
                0x04, // ContextID
                0x00
        } );

        bb.flip();

        VirtualListViewRequestDecorator control = new VirtualListViewRequestDecorator( codec );
        VirtualListViewRequest virtualListView = ( VirtualListViewRequest ) control.decode( bb.array() );

        assertEquals( 1, virtualListView.getBeforeCount() );
        assertEquals( 1, virtualListView.getAfterCount() );
        assertTrue( virtualListView.hasOffset() );
        assertEquals( 1, virtualListView.getOffset() );
        assertEquals( 1, virtualListView.getContentCount() );
        assertNull( virtualListView.getContextId() );

        ByteBuffer encoded = ( ( VirtualListViewRequestDecorator ) virtualListView ).encode(
            ByteBuffer.allocate( ( ( VirtualListViewRequestDecorator ) virtualListView ).computeLength() ) );
        assertEquals( "0x30 0x0E 0x02 0x01 0x01 0x02 0x01 0x01 0xA0 0x06 0x02 0x01 0x01 0x02 0x01 0x01 ",
            Strings.dumpBytes( encoded.array() ) );
    }


    @Test
    public void testDecodeAssertionValueWithContextID() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x14 );

        bb.put( new byte[]
            {
                0x30, 0x12,
                0x02, 0x01, 0x01, // beforeCount
                0x02,
                0x01,
                0x01, // afterCount
                ( byte ) 0x81,
                0x04,
                'a',
                'b',
                'c',
                'd',
                0x04,
                0x04,
                'a',
                'b',
                'c',
                'd'
        } );

        bb.flip();

        VirtualListViewRequestDecorator control = new VirtualListViewRequestDecorator( codec );
        VirtualListViewRequest virtualListView = ( VirtualListViewRequest ) control.decode( bb.array() );

        assertEquals( 1, virtualListView.getBeforeCount() );
        assertEquals( 1, virtualListView.getAfterCount() );
        assertTrue( virtualListView.hasAssertionValue() );
        assertEquals( "abcd", Strings.utf8ToString( virtualListView.getAssertionValue() ) );
        assertEquals( "abcd", Strings.utf8ToString( virtualListView.getContextId() ) );

        ByteBuffer encoded = ( ( VirtualListViewRequestDecorator ) virtualListView ).encode(
            ByteBuffer.allocate( ( ( VirtualListViewRequestDecorator ) virtualListView ).computeLength() ) );
        assertEquals( Strings.dumpBytes( bb.array() ), Strings.dumpBytes( encoded.array() ) );
    }


    @Test
    public void testDecodeAssertionValueEmptyContextID() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x10 );

        bb.put( new byte[]
            {
                0x30, 0x0E,
                0x02, 0x01, 0x01, // beforeCount
                0x02,
                0x01,
                0x01, // afterCount
                ( byte ) 0x81,
                0x04,
                'a',
                'b',
                'c',
                'd',
                0x04,
                0x00
        } );

        bb.flip();

        VirtualListViewRequestDecorator control = new VirtualListViewRequestDecorator( codec );
        VirtualListViewRequest virtualListView = ( VirtualListViewRequest ) control.decode( bb.array() );

        assertEquals( 1, virtualListView.getBeforeCount() );
        assertEquals( 1, virtualListView.getAfterCount() );
        assertTrue( virtualListView.hasAssertionValue() );
        assertEquals( "abcd", Strings.utf8ToString( virtualListView.getAssertionValue() ) );
        assertNull( virtualListView.getContextId() );

        ByteBuffer encoded = ( ( VirtualListViewRequestDecorator ) virtualListView ).encode(
            ByteBuffer.allocate( ( ( VirtualListViewRequestDecorator ) virtualListView ).computeLength() ) );
        assertEquals( "0x30 0x0C 0x02 0x01 0x01 0x02 0x01 0x01 0x81 0x04 0x61 0x62 0x63 0x64 ",
            Strings.dumpBytes( encoded.array() ) );
    }


    @Test
    public void testDecodeAssertionValueWithoutContextID() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0E );

        bb.put( new byte[]
            {
                0x30, 0x0C,
                0x02, 0x01, 0x01, // beforeCount
                0x02,
                0x01,
                0x01, // afterCount
                ( byte ) 0x81,
                0x04,
                'a',
                'b',
                'c',
                'd'
        } );

        bb.flip();

        VirtualListViewRequestDecorator control = new VirtualListViewRequestDecorator( codec );
        VirtualListViewRequest virtualListView = ( VirtualListViewRequest ) control.decode( bb.array() );

        assertEquals( 1, virtualListView.getBeforeCount() );
        assertEquals( 1, virtualListView.getAfterCount() );
        assertTrue( virtualListView.hasAssertionValue() );
        assertEquals( "abcd", Strings.utf8ToString( virtualListView.getAssertionValue() ) );
        assertNull( virtualListView.getContextId() );

        ByteBuffer encoded = ( ( VirtualListViewRequestDecorator ) virtualListView ).encode(
            ByteBuffer.allocate( ( ( VirtualListViewRequestDecorator ) virtualListView ).computeLength() ) );
        assertEquals( Strings.dumpBytes( bb.array() ), Strings.dumpBytes( encoded.array() ) );
    }


    @Test(expected = DecoderException.class)
    public void testDecodeEmptySequence() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x2 );

        bb.put( new byte[]
            {
                0x30, 0x00
        } );

        bb.flip();

        VirtualListViewRequestDecorator control = new VirtualListViewRequestDecorator( codec );
        VirtualListViewRequest virtualListView = ( VirtualListViewRequest ) control.decode( bb.array() );
        fail();
    }


    @Test(expected = DecoderException.class)
    public void testDecodeNoBeforeCount() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x13 );

        bb.put( new byte[]
            {
                0x30, 0x11,
                0x02,
                0x01,
                0x01, // afterCount
                ( byte ) 0xA0,
                0x06,
                0x02, // offset
                0x01,
                0x01,
                0x02, // contentCount
                0x01,
                0x01,
                0x04, // ContextID
                0x04,
                'a',
                'b',
                'c',
                'd'
        } );

        bb.flip();

        VirtualListViewRequestDecorator control = new VirtualListViewRequestDecorator( codec );
        VirtualListViewRequest virtualListView = ( VirtualListViewRequest ) control.decode( bb.array() );
    }


    @Test(expected = DecoderException.class)
    public void testDecodeNoAfterCount() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x13 );

        bb.put( new byte[]
            {
                0x30, 0x11,
                0x02, 0x01, 0x01, // beforeCount
                ( byte ) 0xA0,
                0x06,
                0x02, // offset
                0x01,
                0x01,
                0x02, // contentCount
                0x01,
                0x01,
                0x04, // ContextID
                0x04,
                'a',
                'b',
                'c',
                'd'
        } );

        bb.flip();

        VirtualListViewRequestDecorator control = new VirtualListViewRequestDecorator( codec );
        VirtualListViewRequest virtualListView = ( VirtualListViewRequest ) control.decode( bb.array() );
    }


    @Test(expected = DecoderException.class)
    public void testDecodeNoTarget() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0E );

        bb.put( new byte[]
            {
                0x30, 0x0C,
                0x02, 0x01, 0x01, // beforeCount
                0x02,
                0x01,
                0x01, // afterCount
                0x04, // ContextID
                0x04,
                'a',
                'b',
                'c',
                'd'
        } );

        bb.flip();

        VirtualListViewRequestDecorator control = new VirtualListViewRequestDecorator( codec );
        VirtualListViewRequest virtualListView = ( VirtualListViewRequest ) control.decode( bb.array() );
    }


    @Test(expected = DecoderException.class)
    public void testDecodeEmptyByOffset() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x10 );

        bb.put( new byte[]
            {
                0x30, 0x0E,
                0x02, 0x01, 0x01, // beforeCount
                0x02,
                0x01,
                0x01, // afterCount
                ( byte ) 0xA0,
                0x00,
                0x04, // ContextID
                0x04,
                'a',
                'b',
                'c',
                'd'
        } );

        bb.flip();

        VirtualListViewRequestDecorator control = new VirtualListViewRequestDecorator( codec );
        VirtualListViewRequest virtualListView = ( VirtualListViewRequest ) control.decode( bb.array() );
    }


    @Test
    public void testDecodeEmptyAssertionValue() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x10 );

        bb.put( new byte[]
            {
                0x30, 0x0E,
                0x02, 0x01, 0x01, // beforeCount
                0x02,
                0x01,
                0x01, // afterCount
                ( byte ) 0x81,
                0x00,
                0x04, // ContextID
                0x04,
                'a',
                'b',
                'c',
                'd'
        } );

        bb.flip();

        VirtualListViewRequestDecorator control = new VirtualListViewRequestDecorator( codec );
        VirtualListViewRequest virtualListView = ( VirtualListViewRequest ) control.decode( bb.array() );

        assertEquals( 1, virtualListView.getBeforeCount() );
        assertEquals( 1, virtualListView.getAfterCount() );
        assertTrue( virtualListView.hasAssertionValue() );
        assertEquals( "", Strings.utf8ToString( virtualListView.getAssertionValue() ) );
        assertEquals( "abcd", Strings.utf8ToString( virtualListView.getContextId() ) );

        ByteBuffer encoded = ( ( VirtualListViewRequestDecorator ) virtualListView ).encode(
            ByteBuffer.allocate( ( ( VirtualListViewRequestDecorator ) virtualListView ).computeLength() ) );
        assertEquals( Strings.dumpBytes( bb.array() ), Strings.dumpBytes( encoded.array() ) );
    }


    @Test(expected = DecoderException.class)
    public void testDecodeByOffsetNoOffsetOrContentCount() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x13 );

        bb.put( new byte[]
            {
                0x30, 0x11,
                0x02, 0x01, 0x01, // beforeCount
                0x02,
                0x01,
                0x01, // afterCount
                ( byte ) 0xA0,
                0x03,
                0x02,
                0x01,
                0x01,
                0x04, // ContextID
                0x04,
                'a',
                'b',
                'c',
                'd'
        } );

        bb.flip();

        VirtualListViewRequestDecorator control = new VirtualListViewRequestDecorator( codec );
        VirtualListViewRequest virtualListView = ( VirtualListViewRequest ) control.decode( bb.array() );
    }


    @Test(expected = DecoderException.class)
    public void testDecodeByOffsetWrongOffset() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x16 );

        bb.put( new byte[]
            {
                0x30, 0x14,
                0x02, 0x01, 0x01, // beforeCount
                0x02,
                0x01,
                0x01, // afterCount
                ( byte ) 0xA0,
                0x06,
                0x02,
                0x01,
                0x00,
                0x02,
                0x01,
                0x01,
                0x04, // ContextID
                0x04,
                'a',
                'b',
                'c',
                'd'
        } );

        bb.flip();

        VirtualListViewRequestDecorator control = new VirtualListViewRequestDecorator( codec );
        VirtualListViewRequest virtualListView = ( VirtualListViewRequest ) control.decode( bb.array() );
    }
}
