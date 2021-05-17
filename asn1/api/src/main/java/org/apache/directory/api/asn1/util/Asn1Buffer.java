/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.api.asn1.util;

import java.nio.ByteBuffer;

/**
 * A buffer used to store an encoding PDU. It's auto-extended, and
 * filled by the end.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class Asn1Buffer
{
    /** The buffer default size */
    private static final int DEFAULT_SIZE = 1024;

    /** The current position in the buffer */
    private int pos = 0;

    /** A buffer to store the encoded PDU */
    private byte[] buffer;
    
    
    /**
     * Creates a new Asn1Buffer instance
     */
    public Asn1Buffer()
    {
        buffer = new byte[DEFAULT_SIZE];
    }


    /**
     * @return The current position in the buffer
     */
    public int getPos()
    {
        return pos;
    }


    /**
     * Set the current position in the buffer
     * 
     * @param pos The position to move the buffer to
     */
    public void setPos( int pos )
    {
        this.pos = pos;
    }


    /**
     * Store a byte at the current position in the buffer
     *
     * @param b The byte to store
     */
    public void put( byte b )
    {
        if ( pos == buffer.length )
        {
            // The buffer needs to be reallocated, its too small
            extend( 1 );
        }

        pos++;
        buffer[buffer.length - pos] = b;
    }


    /**
     * Store some bytes at the current position in the buffer
     *
     * @param bytes The bytes to store
     */
    public void put( byte[] bytes )
    {
        if ( pos + bytes.length > buffer.length )
        {
            // The buffer needs to be reallocated, its too small
            extend( bytes.length );
        }


        pos += bytes.length;
        System.arraycopy( bytes, 0, buffer, buffer.length - pos, bytes.length );
    }


    /**
     * Extend the buffer
     * 
     * @param size The new buffer size
     */
    private void extend( int size )
    {
        // The buffer needs to be reallocated, it's too small
        int newSize = ( ( size + buffer.length ) / DEFAULT_SIZE ) * DEFAULT_SIZE;

        if ( size % DEFAULT_SIZE != 0 )
        {
            newSize += DEFAULT_SIZE;
        }

        byte[] newBuffer = new byte[newSize];
        System.arraycopy( buffer, 0, newBuffer, newSize - buffer.length, buffer.length );

        buffer = newBuffer;
    }


    /**
     * @return The stored encoded PDU.
     */
    public ByteBuffer getBytes()
    {
        ByteBuffer result = ByteBuffer.allocate( pos );

        result.put( buffer, buffer.length - pos, pos );
        result.flip();

        return result;
    }


    /**
     * @return The buffer size (ie the maximum number of bytes that can be
     * added to this bffder before it gets extended).
     */
    public int getSize()
    {
        return buffer.length;
    }


    /**
     * Clear the position, emptying the buffer. If it has grown, reallocate it
     * to its initial size.
     */
    public void clear()
    {
        if ( buffer.length > DEFAULT_SIZE )
        {
            buffer = new byte[DEFAULT_SIZE];
        }

        pos = 0;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return "[" + buffer.length + ", " + pos + "] '"
            + Asn1StringUtils.dumpBytes( buffer, buffer.length - pos, pos ) + '\'';
    }
}
