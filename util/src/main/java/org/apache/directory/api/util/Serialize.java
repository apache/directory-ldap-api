/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.directory.api.util;


/**
 * A class containing static methods used to serialize and deserialize base types
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class Serialize
{
    /** The serialized value for TRUE */
    public static final byte TRUE = 0x01;

    /** The serialized value for FALSE */
    public static final byte FALSE = 0x00;


    private Serialize()
    {
    }


    /**
     * Write an integer into a buffer at a given position
     * 
     * @param value The value to serialize
     * @param buffer The buffer to store the value into
     * @param pos The position where we serialize the integer
     * @return The new position in the byte[]
     */
    public static int serialize( int value, byte[] buffer, int pos )
    {
        if ( buffer.length - pos < 4 )
        {
            throw new ArrayIndexOutOfBoundsException();
        }

        buffer[pos++] = ( byte ) ( ( value >>> 24 ) & 0xFF );
        buffer[pos++] = ( byte ) ( ( value >>> 16 ) & 0xFF );
        buffer[pos++] = ( byte ) ( ( value >>> 8 ) & 0xFF );
        buffer[pos++] = ( byte ) ( ( value >>> 0 ) & 0xFF );

        return pos;
    }


    /**
     * Write a byte[] into a buffer at a given position
     * 
     * @param value The value to serialize
     * @param buffer The buffer to store the value into
     * @param pos The position where we serialize the byte[]
     * @return The new position in the byte[]
     */
    public static int serialize( byte[] value, byte[] buffer, int pos )
    {
        if ( buffer.length - pos < 4 + value.length )
        {
            throw new ArrayIndexOutOfBoundsException();
        }

        buffer[pos++] = ( byte ) ( ( value.length >>> 24 ) & 0xFF );
        buffer[pos++] = ( byte ) ( ( value.length >>> 16 ) & 0xFF );
        buffer[pos++] = ( byte ) ( ( value.length >>> 8 ) & 0xFF );
        buffer[pos++] = ( byte ) ( ( value.length >>> 0 ) & 0xFF );

        System.arraycopy( value, 0, buffer, pos, value.length );

        return pos + value.length;
    }


    /**
     * Read an integer from a buffer at a given position
     * 
     * @param buffer The buffer containing the serialized integer
     * @param pos The position from which we will read an integer
     * @return the deserialized integer
     */
    public static int deserializeInt( byte[] buffer, int pos )
    {
        if ( buffer.length - pos < 4 )
        {
            throw new ArrayIndexOutOfBoundsException();
        }

        return ( buffer[pos] << 24 ) + ( buffer[pos + 1] << 16 ) + ( buffer[pos + 2] << 8 ) + ( buffer[pos + 3] << 0 );
    }


    /**
     * Read a byte[] from a buffer at a given position
     * 
     * @param buffer The buffer containing the serialized byte[]
     * @param pos The position from which we will read a byte[]
     * @return the deserialized byte[]
     */
    public static byte[] deserializeBytes( byte[] buffer, int pos )
    {
        if ( buffer.length - pos < 4 )
        {
            throw new ArrayIndexOutOfBoundsException();
        }

        int len = deserializeInt( buffer, pos );
        pos += 4;

        if ( len > 0 )
        {
            if ( buffer.length - pos < len )
            {
                throw new ArrayIndexOutOfBoundsException();
            }

            byte[] result = new byte[len];

            System.arraycopy( buffer, pos, result, 0, len );

            return result;
        }
        else
        {
            return Strings.EMPTY_BYTES;
        }
    }


    /**
     * Read a boolean from a buffer at a given position
     * 
     * @param buffer The buffer containing the serialized boolean
     * @param pos The position from which we will read a boolean
     * @return the deserialized boolean
     */
    public static boolean deserializeBoolean( byte[] buffer, int pos )
    {
        if ( buffer.length - pos < 1 )
        {
            throw new ArrayIndexOutOfBoundsException();
        }

        byte value = buffer[pos];

        return ( value != 0x00 );
    }
}
