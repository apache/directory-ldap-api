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
package org.apache.directory.api.ldap.codec.api;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.filterchain.IoFilter.NextFilter;
import org.apache.mina.core.session.DummySession;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.write.DefaultWriteRequest;
import org.apache.mina.core.write.WriteRequest;
import org.apache.mina.filter.FilterEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests for the received SASL length prefix validation and reassembly
 * in {@link SaslFilter}.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class SaslFilterTest
{
    /**
     * A SaslClient stub that negotiated auth-int with the given max buffer size,
     * and whose unwrap is the identity function.
     */
    private SaslClient newSaslClient( final String maxBuffer )
    {
        return new SaslClient()
        {
            @Override
            public String getMechanismName()
            {
                return "DUMMY";
            }


            @Override
            public boolean hasInitialResponse()
            {
                return false;
            }


            @Override
            public byte[] evaluateChallenge( byte[] challenge ) throws SaslException
            {
                return new byte[0];
            }


            @Override
            public boolean isComplete()
            {
                return true;
            }


            @Override
            public byte[] unwrap( byte[] incoming, int offset, int len ) throws SaslException
            {
                byte[] result = new byte[len];
                System.arraycopy( incoming, offset, result, 0, len );
                return result;
            }


            @Override
            public byte[] wrap( byte[] outgoing, int offset, int len ) throws SaslException
            {
                byte[] result = new byte[len];
                System.arraycopy( outgoing, offset, result, 0, len );
                return result;
            }


            @Override
            public Object getNegotiatedProperty( String propName )
            {
                if ( Sasl.QOP.equals( propName ) )
                {
                    return "auth-int";
                }

                if ( Sasl.MAX_BUFFER.equals( propName ) )
                {
                    return maxBuffer;
                }

                return null;
            }


            @Override
            public void dispose() throws SaslException
            {
            }
        };
    }

    /**
     * A NextFilter that records the messages forwarded to it.
     */
    private static final class CapturingNextFilter implements NextFilter
    {
        private final List<Object> messages = new ArrayList<>();


        @Override
        public void sessionCreated( IoSession session )
        {
        }


        @Override
        public void sessionOpened( IoSession session )
        {
        }


        @Override
        public void sessionClosed( IoSession session )
        {
        }


        @Override
        public void sessionIdle( IoSession session, IdleStatus status )
        {
        }


        @Override
        public void exceptionCaught( IoSession session, Throwable cause )
        {
        }


        @Override
        public void inputClosed( IoSession session )
        {
        }


        @Override
        public void messageReceived( IoSession session, Object message )
        {
            messages.add( message );
        }


        @Override
        public void messageSent( IoSession session, WriteRequest writeRequest )
        {
        }


        @Override
        public void filterWrite( IoSession session, WriteRequest writeRequest )
        {
        }


        @Override
        public void filterClose( IoSession session )
        {
        }


        @Override
        public void event( IoSession session, FilterEvent event )
        {
        }
    }


    /**
     * A negative length prefix (sign bit flipped) must fail through the
     * SaslException error path, not with a NegativeArraySizeException.
     */
    @Test
    public void testNegativeLengthPrefixIsRejected() throws Exception
    {
        SaslFilter filter = new SaslFilter( newSaslClient( "65536" ) );
        IoSession session = new DummySession();

        IoBuffer buf = IoBuffer.allocate( 8 );
        buf.putInt( 0xFFFFFFFF );
        buf.putInt( 0 );
        buf.flip();

        assertThrows( SaslException.class, () -> filter.messageReceived( new CapturingNextFilter(), session, buf ) );
    }


    /**
     * A zero length prefix must be rejected as well.
     */
    @Test
    public void testZeroLengthPrefixIsRejected() throws Exception
    {
        SaslFilter filter = new SaslFilter( newSaslClient( "65536" ) );
        IoSession session = new DummySession();

        IoBuffer buf = IoBuffer.allocate( 4 );
        buf.putInt( 0 );
        buf.flip();

        assertThrows( SaslException.class, () -> filter.messageReceived( new CapturingNextFilter(), session, buf ) );
    }


    /**
     * A length prefix larger than the negotiated max buffer size must fail
     * through the SaslException error path.
     */
    @Test
    public void testTooLargeLengthPrefixIsRejected() throws Exception
    {
        SaslFilter filter = new SaslFilter( newSaslClient( "65536" ) );
        IoSession session = new DummySession();

        IoBuffer buf = IoBuffer.allocate( 4 );
        buf.putInt( 65537 );
        buf.flip();

        assertThrows( SaslException.class, () -> filter.messageReceived( new CapturingNextFilter(), session, buf ) );
    }


    /**
     * A length prefix split across two TCP fragments must be reassembled
     * instead of throwing a BufferUnderflowException.
     */
    @Test
    public void testLengthPrefixSplitAcrossFragments() throws Exception
    {
        SaslFilter filter = new SaslFilter( newSaslClient( "65536" ) );
        IoSession session = new DummySession();
        CapturingNextFilter nextFilter = new CapturingNextFilter();

        byte[] payload = new byte[]
            { 'a', 'b', 'c', 'd' };

        // First fragment: only 2 of the 4 length prefix bytes
        IoBuffer fragment1 = IoBuffer.wrap( new byte[]
            { 0x00, 0x00 } );
        filter.messageReceived( nextFilter, session, fragment1 );
        assertTrue( nextFilter.messages.isEmpty() );

        // Second fragment: remaining prefix bytes plus the payload
        IoBuffer fragment2 = IoBuffer.allocate( 2 + payload.length );
        fragment2.put( ( byte ) 0x00 );
        fragment2.put( ( byte ) payload.length );
        fragment2.put( payload );
        fragment2.flip();
        filter.messageReceived( nextFilter, session, fragment2 );

        assertEquals( 1, nextFilter.messages.size() );
        IoBuffer forwarded = ( IoBuffer ) nextFilter.messages.get( 0 );
        byte[] forwardedBytes = new byte[forwarded.remaining()];
        forwarded.get( forwardedBytes );
        assertArrayEquals( payload, forwardedBytes );
    }


    /**
     * A negotiated max buffer size that leaves no room for data must fail
     * with a SaslException instead of looping forever in filterWrite.
     */
    @Test
    public void testTooSmallNegotiatedBufferSizeFailsWrite() throws Exception
    {
        SaslFilter filter = new SaslFilter( newSaslClient( "200" ) );
        IoSession session = new DummySession();

        IoBuffer buf = IoBuffer.wrap( new byte[]
            { 'a', 'b', 'c', 'd' } );

        assertThrows( SaslException.class,
            () -> filter.filterWrite( new CapturingNextFilter(), session, new DefaultWriteRequest( buf ) ) );
    }
}
