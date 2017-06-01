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
package org.apache.directory.ldap.client.template;


import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;


/**
 * A buffer for storing sensitive information like passwords.  It provides 
 * useful operations for characters such as character encoding/decoding, 
 * whitespace trimming, and lowercasing.  It can be cleared out when operations
 * are complete.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class MemoryClearingBuffer
{
    private static final Charset UTF8 = Charset.forName( "UTF-8" );
    private byte[] computedBytes;
    private char[] computedChars;
    private byte[] originalBytes;
    private char[] originalChars;
    private char[] precomputedChars;


    private MemoryClearingBuffer( byte[] originalBytes, char[] originalChars, boolean trim, boolean lowerCase )
    {
        this.originalBytes = originalBytes;
        this.originalChars = originalChars;

        if ( trim || lowerCase )
        {
            if ( this.originalChars == null )
            {
                throw new UnsupportedOperationException( "trim and lowerCase only applicable to char[]" );
            }

            char[] working = Arrays.copyOf( originalChars, originalChars.length );
            int startIndex = 0;
            int endIndex = working.length;

            if ( trim )
            {
                // ltrim
                for ( ; startIndex < working.length; startIndex++ )
                {
                    if ( !Character.isWhitespace( working[startIndex] ) )
                    {
                        break;
                    }
                }

                // rtrim
                for ( endIndex--; endIndex > startIndex; endIndex-- )
                {
                    if ( !Character.isWhitespace( working[endIndex] ) )
                    {
                        break;
                    }
                }
                endIndex++;
            }

            if ( lowerCase )
            {
                // lower case
                for ( int i = startIndex; i < endIndex; i++ )
                {
                    working[i] = Character.toLowerCase( working[i] );
                }
            }

            this.precomputedChars = new char[endIndex - startIndex];
            System.arraycopy( working, startIndex, this.precomputedChars, 0, endIndex - startIndex );
        }
        else
        {
            this.precomputedChars = this.originalChars;
        }
    }


    /**
     * Creates a new instance of MemoryClearingBuffer from a 
     * <code>byte[]</code>.
     *
     * @param bytes A byte[]
     * @return A buffer
     */
    public static MemoryClearingBuffer newInstance( byte[] bytes )
    {
        return new MemoryClearingBuffer( bytes, null, false, false );
    }


    /**
     * Creates a new instance of MemoryClearingBuffer from a 
     * <code>char[]</code>.
     *
     * @param chars A char[]
     * @return A buffer
     */
    public static MemoryClearingBuffer newInstance( char[] chars )
    {
        return new MemoryClearingBuffer( null, chars, false, false );
    }


    /**
     * Creates a new instance of MemoryClearingBuffer from a 
     * <code>char[]</code>, optionally performing whitespace trimming and
     * conversion to lower case.
     *
     * @param chars A char[]
     * @param trim If true, whitespace will be trimmed off of both ends of the
     * <code>char[]</code>
     * @param lowerCase If true, the characters will be converted to lower case
     * @return A buffer
     */
    public static MemoryClearingBuffer newInstance( char[] chars, boolean trim, boolean lowerCase )
    {
        return new MemoryClearingBuffer( null, chars, trim, lowerCase );
    }


    /**
     *  Clears the buffer out, filling its cells with null.
     */
    public void clear()
    {
        // clear out computed memory
        if ( computedBytes != null )
        {
            Arrays.fill( computedBytes, ( byte ) 0 );
        }
        if ( computedChars != null )
        {
            Arrays.fill( computedChars, '0' );
        }
        if ( precomputedChars != null && precomputedChars != this.originalChars )
        {
            // only nullify if NOT originalChars
            Arrays.fill( precomputedChars, '0' );
        }

        computedBytes = null;
        computedChars = null;
        originalBytes = null;
        originalChars = null;
        precomputedChars = null;
    }


    /**
     * Returns a UTF8 encoded <code>byte[]</code> representation of the 
     * <code>char[]</code> used to create this buffer.
     * 
     * @return A byte[]
     */
    byte[] getComputedBytes()
    {
        if ( computedBytes == null )
        {
            ByteBuffer byteBuffer = UTF8.encode(
                CharBuffer.wrap( precomputedChars, 0, precomputedChars.length ) );
            computedBytes = new byte[byteBuffer.remaining()];
            byteBuffer.get( computedBytes );

            // clear out the temporary bytebuffer
            byteBuffer.flip();
            byte[] nullifier = new byte[byteBuffer.limit()];
            Arrays.fill( nullifier, ( byte ) 0 );
            byteBuffer.put( nullifier );
        }
        return computedBytes;
    }


    /**
     * Returns a UTF8 decoded <code>char[]</code> representation of the 
     * <code>byte[]</code> used to create this buffer.
     *
     * @return A char[]
     */
    private char[] getComputedChars()
    {
        if ( computedChars == null )
        {
            CharBuffer charBuffer = UTF8.decode(
                ByteBuffer.wrap( originalBytes, 0, originalBytes.length ) );
            computedChars = new char[charBuffer.remaining()];
            charBuffer.get( computedChars );

            // clear out the temporary bytebuffer
            charBuffer.flip();
            char[] nullifier = new char[charBuffer.limit()];
            Arrays.fill( nullifier, ( char ) 0 );
            charBuffer.put( nullifier );
        }
        return computedChars;
    }


    /**
     * Returns the <code>byte[]</code> used to create this buffer, or 
     * getComputedBytes() if created with a <code>char[]</code>.
     *
     * @return A byte[]
     */
    public byte[] getBytes()
    {
        return originalBytes == null
            ? getComputedBytes()
            : originalBytes;
    }

    /**
     * Returns the <code>char[]</code> used to create this buffer, or 
     * getComputedChars() if created with a <code>byte[]</code>.
     *
     * @return A byte[]
     */
    public char[] getChars()
    {
        return precomputedChars == null
            ? getComputedChars()
            : precomputedChars;
    }
}