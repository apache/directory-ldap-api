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
package org.apache.directory.api.util;


import org.apache.directory.api.i18n.I18n;


/**
 * A dynamically growing byte[]. 
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ByteBuffer
{
    /** the default initial buffer size */
    private static final int DEFAULT_INITIAL_SIZE = 10;

    /** the initial size of the buffer in number of bytes: also increment for allocations */
    private final int initialSize;

    /** the position into the buffer */
    private int pos = 0;

    /** the bytes of the buffer */
    private byte[] buf;

    /**
     * Create a default ByteBuffer capable of holding 10 bytes
     */
    public ByteBuffer()
    {
        this( DEFAULT_INITIAL_SIZE );
    }


    /**
     * Creates a ByteBuffer which has an initialze size
     *  
     * @param initialSize The initial buffer size
     */
    public ByteBuffer( int initialSize )
    {
        if ( initialSize <= 0 )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04354 ) );
        }

        this.initialSize = initialSize;
        this.buf = new byte[initialSize];
    }


    /**
     * Reset the Buffer position to 0. Every new added byte will be put on position 0.
     * Note that whatever this buffer contained before a call to the clear() method
     * will not be removed.
     */
    public final void clear()
    {
        pos = 0;
    }


    /**
     * @return The current position in the buffer
     */
    public final int position()
    {
        return pos;
    }


    /**
     * @return The number of bytes that can be added into this buffer
     */
    public final int capacity()
    {
        return buf.length;
    }


    /**
     * Returns the byte at a given position. Note that no control is done
     * on the position validity.
     * 
     * @param i The position
     * @return The byte at the given position in the buffer
     */
    public final byte get( int i )
    {
        return buf[i];
    }


    /**
     * Get's the bytes, the backing store for this buffer.  Note
     * that you need to use the position index to determine where
     * to stop reading from this buffer.
     * 
     * @return The interned Byte[]
     */
    public final byte[] buffer()
    {
        return buf;
    }


    /**
     * Get's a copy of the bytes used.
     * 
     * @return A copy of the interned Byte[]
     */
    public final byte[] copyOfUsedBytes()
    {
        byte[] copy = new byte[pos];
        System.arraycopy( buf, 0, copy, 0, pos );
        return copy;
    }


    /**
     * Appends the bytes to this buffer.
     * 
     * @param bytes The byte[] to append to the buffer
     */
    public final void append( byte[] bytes )
    {
        if ( pos + bytes.length > buf.length )
        {
            growBuffer( bytes.length );
        }

        System.arraycopy( bytes, 0, buf, pos, bytes.length );
        pos += bytes.length;
    }


    /**
     * Appends a byte to this buffer.
     * 
     * @param b The byte to append to the buffer
     */
    public final void append( byte b )
    {
        if ( pos >= buf.length )
        {
            growBuffer();
        }

        buf[pos] = b;
        pos++;
    }


    /**
     * Appends an int to this buffer.  WARNING: the int is truncated to 
     * a byte value.
     * 
     * @param val The integer to append to the buffer
     */
    public final void append( int val )
    {
        if ( pos >= buf.length )
        {
            growBuffer();
        }

        buf[pos] = ( byte ) val;
        pos++;
    }


    private void growBuffer( int size )
    {
        if ( size > initialSize )
        {
            byte[] copy = new byte[buf.length + size];
            System.arraycopy( buf, 0, copy, 0, pos );
            this.buf = copy;
        }
        else
        {
            byte[] copy = new byte[buf.length + initialSize];
            System.arraycopy( buf, 0, copy, 0, pos );
            this.buf = copy;
        }
    }


    private void growBuffer()
    {
        byte[] copy = new byte[buf.length + initialSize];
        System.arraycopy( buf, 0, copy, 0, pos );
        this.buf = copy;
    }
}
