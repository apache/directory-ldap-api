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

package org.apache.directory.api.asn1.util;

/**
 * A buffer used to store an encoding PDU. It's auto-extended, and
 * filled by the end.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class Asn1Buffer2
{
    /** The buffer default size */
    private static final int DEFAULT_SIZE = 1024;

    /** The current position in the buffer */
    private int pos = 0;

    /** The current size */
    private int size = DEFAULT_SIZE;

    /** The internal buffer storage */
    private class InternalBuffer
    {
        /** A buffer to store the encoded PDU */
        private byte[] buffer = new byte[DEFAULT_SIZE];

        /** The next buffer, if any */
        private InternalBuffer next;
    }

    /** The current internal buffer */
    private InternalBuffer currentBuffer;


    /**
     * Create a new instance of Asn1Buffer2
     */
    public Asn1Buffer2()
    {
        currentBuffer = new InternalBuffer();
    }


    /**
     * @return The current position in the buffer
     */
    public int getPos()
    {
        return pos;
    }


    /**
     * Store a byte at the current position in the buffer
     *
     * @param b The byte to store
     */
    public void put( byte b )
    {
        if ( pos == size )
        {
            // The buffer needs to be reallocated, its too small
            extend();
        }

        currentBuffer.buffer[size - pos - 1] = b;
        pos++;
    }


    /**
     * Store some bytes at the current position in the buffer
     *
     * @param bytes The bytes to store
     */
    public void put( byte[] bytes )
    {
        int dataLength = bytes.length;

        while ( true )
        {
            int room = size - pos;

            if ( dataLength > room )
            {
                // First fulfill the current buffer
                System.arraycopy(
                    bytes,
                    dataLength - room,
                    currentBuffer,
                    0,
                    room );

                dataLength -= room;
                pos += room;

                extend();
            }
            else
            {
                // Last bytes are copied in the current buffer
                System.arraycopy(
                    bytes,
                    0,
                    currentBuffer,
                    room - dataLength,
                    dataLength );

                pos += dataLength;

                break;
            }
        }
    }


    /**
     * Extend the buffer
     */
    private void extend()
    {
        InternalBuffer newCurrentBuffer = new InternalBuffer();

        newCurrentBuffer.next = currentBuffer;
        currentBuffer = newCurrentBuffer;
        size += DEFAULT_SIZE;
    }


    /**
     * @return The stored encoded PDU.
     */
    public byte[] getBytes()
    {
        byte[] result = new byte[pos];

        InternalBuffer bufferPtr = currentBuffer;
        int currentPos = 0;
        int dataPos = size - pos;
        int dataLength = DEFAULT_SIZE - dataPos;

        while ( bufferPtr.next != null )
        {
            System.arraycopy(
                bufferPtr,
                dataPos,
                result,
                currentPos,
                dataLength );

            currentPos += dataLength;
            dataPos = 0;
            dataLength = DEFAULT_SIZE;
        }

        return result;
    }


    /**
     * @return The buffer size (ie the maximum number of bytes that can be
     * added to this buffer before it gets extended).
     */
    public int getSize()
    {
        return size;
    }


    /**
     * Clear the position, emptying the buffer. If it has grown, reallocate it
     * to its initial size.
     */
    public void clear()
    {
        pos = 0;
        size = DEFAULT_SIZE;

        // Un-reference the extended buffer. They will be garbage collected.
        while ( currentBuffer.next != null )
        {
            currentBuffer = currentBuffer.next;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append( "[" ).append( size ).append( ", " ).append( pos ).append( "] )" );

        InternalBuffer bufferPtr = currentBuffer;

        while ( bufferPtr.next != null )
        {
            sb.append( "\n    " ).append( Asn1StringUtils.dumpBytes( bufferPtr.buffer ) );
        }

        return sb.toString();
    }
}
