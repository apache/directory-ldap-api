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
package org.apache.directory.api.asn1.ber.tlv;


import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.asn1.util.Asn1StringUtils;
import org.apache.directory.api.asn1.util.BitString;
import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.util.Strings;


/**
 * This class stores the data decoded from a TLV.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class BerValue
{
    /** The data buffer. */
    private byte[] data;

    /** The current position of the last byte in the data buffer */
    private int currentPos;

    /** The encoded byte for a TRUE value */
    public static final byte TRUE_VALUE = ( byte ) 0xFF;

    /** The encoded byte for a FALSE value */
    public static final byte FALSE_VALUE = ( byte ) 0x00;

    /** Pre-encoded PDUs for a TRUE TLV */
    private static final byte[] ENCODED_TRUE = new byte[]
        { 0x01, 0x01, TRUE_VALUE };

    /** Pre-encoded PDUs for a FALSE TLV */
    private static final byte[] ENCODED_FALSE = new byte[]
        { 0x01, 0x01, FALSE_VALUE };

    /** Integer limits for encoding : 0x7F */
    private static final int ONE_BYTE_MAX = ( 1 << 7 ) - 1;

    /** Integer limits for encoding : -0x7F */
    private static final int ONE_BYTE_MIN = -( 1 << 7 );

    /** Integer limits for encoding : 0x7FFF */
    private static final int TWO_BYTE_MAX = ( 1 << 15 ) - 1;

    /** Integer limits for encoding : -0x7FFF */
    private static final int TWO_BYTE_MIN = -( 1 << 15 );

    /** Integer limits for encoding : 0x7FFFFF */
    private static final int THREE_BYTE_MAX = ( 1 << 23 ) - 1;

    /** Integer limits for encoding : -0x7FFFFF */
    private static final int THREE_BYTE_MIN = -( 1 << 23 );

    /** Integer limits for encoding : 0x7FFFFFFF */
    private static final long FOUR_BYTE_MAX = ( 1L << 31 ) - 1L;

    /** Integer limits for encoding : -0x7FFFFFFF */
    private static final long FOUR_BYTE_MIN = -( 1L << 31 );

    /** Integer limits for encoding : 0x7FFFFFFFFF */
    private static final long FIVE_BYTE_MAX = ( 1L << 39 ) - 1L;

    /** Integer limits for encoding : -0x7FFFFFFFFF */
    private static final long FIVE_BYTE_MIN = -( 1L << 39 );

    /** Integer limits for encoding : 0x7FFFFFFFFFFF */
    private static final long SIX_BYTE_MAX = ( 1L << 47 ) - 1L;

    /** Integer limits for encoding : -0x7FFFFFFFFFFF */
    private static final long SIX_BYTE_MIN = -( 1L << 47 );

    /** Integer limits for encoding : 0x7FFFFFFFFFFF */
    private static final long SEVEN_BYTE_MAX = ( 1L << 55 ) - 1L;

    /** Integer limits for encoding : -0x7FFFFFFFFFFF */
    private static final long SEVEN_BYTE_MIN = -( 1L << 55 );


    /**
     * Creates a new Value from a byte[]
     *
     * @param value the associated value
     */
    public BerValue( byte[] value )
    {
        // Do a copy of the byte array
        data = new byte[value.length];
        System.arraycopy( value, 0, data, 0, value.length );
        currentPos = 0;
    }


    /**
     * The default constructor.
     */
    public BerValue()
    {
        data = null;
        currentPos = 0;
    }


    /**
     * Initialize the Value
     *
     * @param size The data size to allocate.
     */
    public void init( int size )
    {
        data = new byte[size];
        currentPos = 0;
    }


    /**
     * Reset the Value so that it can be reused
     */
    public void reset()
    {
        data = null;
        currentPos = 0;
    }


    /**
     * Get the Values'data
     *
     * @return Returns the data.
     */
    public byte[] getData()
    {
        return data;
    }


    /**
     * Set a block of bytes in the Value
     *
     * @param data The data to set.
     */
    public void setData( ByteBuffer data )
    {
        int length = data.remaining();
        data.get( this.data, 0, length );
        currentPos = length;
    }


    /**
     * Append some bytes to the data buffer.
     *
     * @param buffer The data to append.
     */
    public void addData( ByteBuffer buffer )
    {
        int length = buffer.remaining();
        buffer.get( data, currentPos, length );
        currentPos += length;
    }


    /**
     * Set a block of bytes in the Value
     *
     * @param data The data to set.
     */
    public void setData( byte[] data )
    {
        System.arraycopy( data, 0, this.data, 0, data.length );
        currentPos = data.length;
    }


    /**
     * Append some bytes to the data buffer.
     *
     * @param array The data to append.
     */
    public void addData( byte[] array )
    {
        System.arraycopy( array, 0, this.data, currentPos, array.length );
        currentPos = array.length;
    }


    /**
     * Get the current length
     * 
     * @return The number of bytes actually stored
     */
    public int getCurrentLength()
    {
        return currentPos;
    }


    /**
     * Utility function that return the number of bytes necessary to store an
     * integer value. Note that this value must be in [Integer.MIN_VALUE,
     * Integer.MAX_VALUE].
     *
     * @param value The value to store in a byte array
     * @return The number of bytes necessary to store the value.
     */
    public static int getNbBytes( int value )
    {
        if ( ( value >= ONE_BYTE_MIN ) && ( value <= ONE_BYTE_MAX ) )
        {
            return 1;
        }
        else if ( ( value >= TWO_BYTE_MIN ) && ( value <= TWO_BYTE_MAX ) )
        {
            return 2;
        }
        else if ( ( value >= THREE_BYTE_MIN ) && ( value <= THREE_BYTE_MAX ) )
        {
            return 3;
        }
        else
        {
            return 4;
        }
    }


    /**
     * Utility function that return the number of bytes necessary to store a
     * long value. Note that this value must be in [Long.MIN_VALUE,
     * Long.MAX_VALUE].
     *
     * @param value The value to store in a byte array
     * @return The number of bytes necessary to store the value.
     */
    public static int getNbBytes( long value )
    {
        if ( ( value >= ONE_BYTE_MIN ) && ( value <= ONE_BYTE_MAX ) )
        {
            return 1;
        }
        else if ( ( value >= TWO_BYTE_MIN ) && ( value <= TWO_BYTE_MAX ) )
        {
            return 2;
        }
        else if ( ( value >= THREE_BYTE_MIN ) && ( value <= THREE_BYTE_MAX ) )
        {
            return 3;
        }
        else if ( ( value >= FOUR_BYTE_MIN ) && ( value <= FOUR_BYTE_MAX ) )
        {
            return 4;
        }
        else if ( ( value >= FIVE_BYTE_MIN ) && ( value <= FIVE_BYTE_MAX ) )
        {
            return 5;
        }
        else if ( ( value >= SIX_BYTE_MIN ) && ( value <= SIX_BYTE_MAX ) )
        {
            return 6;
        }
        else if ( ( value >= SEVEN_BYTE_MIN ) && ( value <= SEVEN_BYTE_MAX ) )
        {
            return 7;
        }
        else
        {
            return 8;
        }
    }


    /**
     * Utility function that return a byte array representing the Value We must
     * respect the ASN.1 BER encoding scheme :
     * <pre>
     * 1) positive integer
     * - [0 - 0x7F] : 0xVV
     * - [0x80 - 0xFF] : 0x00 0xVV
     * - [0x0100 - 0x7FFF] : 0xVV 0xVV
     * - [0x8000 - 0xFFFF] : 0x00 0xVV 0xVV
     * - [0x010000 - 0x7FFFFF] : 0xVV 0xVV 0xVV
     * - [0x800000 - 0xFFFFFF] : 0x00 0xVV 0xVV 0xVV
     * - [0x01000000 - 0x7FFFFFFF] : 0xVV 0xVV 0xVV 0xVV
     * 2) Negative number - (~value) + 1
     * </pre>
     *
     * @param value The value to store in a byte array
     * @return The byte array representing the value.
     */
    public static byte[] getBytes( int value )
    {
        byte[] bytes;

        if ( value >= 0 )
        {
            if ( ( value >= 0 ) && ( value <= ONE_BYTE_MAX ) )
            {
                bytes = new byte[1];
                bytes[0] = ( byte ) value;
            }
            else if ( ( value > ONE_BYTE_MAX ) && ( value <= TWO_BYTE_MAX ) )
            {
                bytes = new byte[2];
                bytes[1] = ( byte ) value;
                bytes[0] = ( byte ) ( value >> 8 );
            }
            else if ( ( value > TWO_BYTE_MAX ) && ( value <= THREE_BYTE_MAX ) )
            {
                bytes = new byte[3];
                bytes[2] = ( byte ) value;
                bytes[1] = ( byte ) ( value >> 8 );
                bytes[0] = ( byte ) ( value >> 16 );
            }
            else
            {
                bytes = new byte[4];
                bytes[3] = ( byte ) value;
                bytes[2] = ( byte ) ( value >> 8 );
                bytes[1] = ( byte ) ( value >> 16 );
                bytes[0] = ( byte ) ( value >> 24 );
            }
        }
        else
        {
            // On special case : 0x80000000
            if ( value == 0x80000000 )
            {
                bytes = new byte[4];
                bytes[3] = ( byte ) value;
                bytes[2] = ( byte ) ( value >> 8 );
                bytes[1] = ( byte ) ( value >> 16 );
                bytes[0] = ( byte ) ( value >> 24 );
            }
            else
            {
                // We have to compute the complement, and add 1
                if ( value >= 0xFFFFFF80 )
                {
                    bytes = new byte[1];
                    bytes[0] = ( byte ) value;
                }
                else if ( value >= 0xFFFF8000 )
                {
                    bytes = new byte[2];
                    bytes[1] = ( byte ) ( value );
                    bytes[0] = ( byte ) ( value >> 8 );
                }
                else if ( value >= 0xFF800000 )
                {
                    bytes = new byte[3];
                    bytes[2] = ( byte ) value;
                    bytes[1] = ( byte ) ( value >> 8 );
                    bytes[0] = ( byte ) ( value >> 16 );
                }
                else
                {
                    bytes = new byte[4];
                    bytes[3] = ( byte ) value;
                    bytes[2] = ( byte ) ( value >> 8 );
                    bytes[1] = ( byte ) ( value >> 16 );
                    bytes[0] = ( byte ) ( value >> 24 );
                }
            }
        }

        return bytes;
    }


    /**
     * Utility function that return a byte array representing the Value.
     * We must respect the ASN.1 BER encoding scheme : <br>
     * <pre>
     * 1) positive integer
     * - [0 - 0x7F] : 0xVV
     * - [0x80 - 0xFF] : 0x00 0xVV
     * - [0x0100 - 0x7FFF] : 0xVV 0xVV
     * - [0x8000 - 0xFFFF] : 0x00 0xVV 0xVV
     * - [0x010000 - 0x7FFFFF] : 0xVV 0xVV 0xVV
     * - [0x800000 - 0xFFFFFF] : 0x00 0xVV 0xVV 0xVV
     * - [0x01000000 - 0x7FFFFFFF] : 0xVV 0xVV 0xVV 0xVV
     * 2) Negative number - (~value) + 1
     * </pre>
     * They are encoded following the table (the <br>
     * encode bytes are those enclosed by squared braquets) :<br>
     * <br>
     * <pre>
     *   -1                      -&gt; FF FF FF FF FF FF FF [FF]
     *   -127                    -&gt; FF FF FF FF FF FF FF [81]
     *   -128                    -&gt; FF FF FF FF FF FF FF [80]
     *   -129                    -&gt; FF FF FF FF FF FF [FF 7F]
     *   -255                    -&gt; FF FF FF FF FF FF [FF 01]
     *   -256                    -&gt; FF FF FF FF FF FF [FF 00]
     *   -257                    -&gt; FF FF FF FF FF FF [FE FF]
     *   -32767                  -&gt; FF FF FF FF FF FF [80 01]
     *   -32768                  -&gt; FF FF FF FF FF FF [80 00]
     *   -32769                  -&gt; FF FF FF FF FF [FF 7F FF]
     *   -65535                  -&gt; FF FF FF FF FF [FF 00 01]
     *   -65536                  -&gt; FF FF FF FF FF [FF 00 00]
     *   -65537                  -&gt; FF FF FF FF FF [FE FF FF]
     *   -8388607                -&gt; FF FF FF FF FF [80 00 01]
     *   -8388608                -&gt; FF FF FF FF FF [80 00 00]
     *   -8388609                -&gt; FF FF FF FF [FF 7F FF FF]
     *   -16777215               -&gt; FF FF FF FF [FF 00 00 01]
     *   -16777216               -&gt; FF FF FF FF [FF 00 00 00]
     *   -16777217               -&gt; FF FF FF FF [FE FF FF FF]
     *   -2147483647             -&gt; FF FF FF FF [80 00 00 01]
     *   -2147483648             -&gt; FF FF FF FF [80 00 00 00]
     *   -2147483649             -&gt; FF FF FF [FF 7F FF FF FF]
     *   -4294967295             -&gt; FF FF FF [FF 00 00 00 01]
     *   -4294967296             -&gt; FF FF FF [FF 00 00 00 00]
     *   -4294967297             -&gt; FF FF FF [FE FF FF FF FF]
     *   -549755813887           -&gt; FF FF FF [80 00 00 00 01]
     *   -549755813888           -&gt; FF FF FF [80 00 00 00 00]
     *   -549755813889           -&gt; FF FF [FF 7F FF FF FF FF]
     *   -1099511627775          -&gt; FF FF [FF 00 00 00 00 01]
     *   -1099511627776          -&gt; FF FF [FF 00 00 00 00 00]
     *   -1099511627777          -&gt; FF FF [FE FF FF FF FF FF]
     *   -140737488355327        -&gt; FF FF [80 00 00 00 00 01]
     *   -140737488355328        -&gt; FF FF [80 00 00 00 00 00]
     *   -140737488355329        -&gt; FF [FF 7F FF FF FF FF FF]
     *   -281474976710655        -&gt; FF [FF 00 00 00 00 00 01]
     *   -281474976710656        -&gt; FF [FF 00 00 00 00 00 00]
     *   -281474976710657        -&gt; FF [FE FF FF FF FF FF FF]
     *   -36028797018963967      -&gt; FF [80 00 00 00 00 00 01]
     *   -36028797018963968      -&gt; FF [80 00 00 00 00 00 00]
     *   -36028797018963969      -&gt; [FF 7F FF FF FF FF FF FF]
     *   -72057594037927936      -&gt; [FF 00 00 00 00 00 00 00]
     *   -72057594037927937      -&gt; [FE FF FF FF FF FF FF FF]
     *   -9223372036854775807    -&gt; [80 00 00 00 00 00 00 01]
     *   -9223372036854775808    -&gt; [80 00 00 00 00 00 00 00]
     * </pre>
     * @param value The value to store in a byte array
     * @return The byte array representing the value.
     */
    public static byte[] getBytes( long value )
    {
        byte[] bytes;

        if ( value >= 0 )
        {
            if ( ( value >= 0 ) && ( value <= ONE_BYTE_MAX ) )
            {
                bytes = new byte[1];
                bytes[0] = ( byte ) value;
            }
            else if ( ( value > ONE_BYTE_MAX ) && ( value <= TWO_BYTE_MAX ) )
            {
                bytes = new byte[2];
                bytes[1] = ( byte ) value;
                bytes[0] = ( byte ) ( value >> 8 );
            }
            else if ( ( value > TWO_BYTE_MAX ) && ( value <= THREE_BYTE_MAX ) )
            {
                bytes = new byte[3];
                bytes[2] = ( byte ) value;
                bytes[1] = ( byte ) ( value >> 8 );
                bytes[0] = ( byte ) ( value >> 16 );
            }
            else if ( ( value > THREE_BYTE_MAX ) && ( value <= FOUR_BYTE_MAX ) )
            {
                bytes = new byte[4];
                bytes[3] = ( byte ) value;
                bytes[2] = ( byte ) ( value >> 8 );
                bytes[1] = ( byte ) ( value >> 16 );
                bytes[0] = ( byte ) ( value >> 24 );
            }
            else if ( ( value > FOUR_BYTE_MAX ) && ( value <= FIVE_BYTE_MAX ) )
            {
                bytes = new byte[5];
                bytes[4] = ( byte ) value;
                bytes[3] = ( byte ) ( value >> 8 );
                bytes[2] = ( byte ) ( value >> 16 );
                bytes[1] = ( byte ) ( value >> 24 );
                bytes[0] = ( byte ) ( value >> 32 );
            }
            else if ( ( value > FIVE_BYTE_MAX ) && ( value <= SIX_BYTE_MAX ) )
            {
                bytes = new byte[6];
                bytes[5] = ( byte ) value;
                bytes[4] = ( byte ) ( value >> 8 );
                bytes[3] = ( byte ) ( value >> 16 );
                bytes[2] = ( byte ) ( value >> 24 );
                bytes[1] = ( byte ) ( value >> 32 );
                bytes[0] = ( byte ) ( value >> 40 );
            }
            else if ( ( value > SIX_BYTE_MAX ) && ( value <= SEVEN_BYTE_MAX ) )
            {
                bytes = new byte[7];
                bytes[6] = ( byte ) value;
                bytes[5] = ( byte ) ( value >> 8 );
                bytes[4] = ( byte ) ( value >> 16 );
                bytes[3] = ( byte ) ( value >> 24 );
                bytes[2] = ( byte ) ( value >> 32 );
                bytes[1] = ( byte ) ( value >> 40 );
                bytes[0] = ( byte ) ( value >> 48 );
            }
            else
            {
                bytes = new byte[8];
                bytes[7] = ( byte ) value;
                bytes[6] = ( byte ) ( value >> 8 );
                bytes[5] = ( byte ) ( value >> 16 );
                bytes[4] = ( byte ) ( value >> 24 );
                bytes[3] = ( byte ) ( value >> 32 );
                bytes[2] = ( byte ) ( value >> 40 );
                bytes[1] = ( byte ) ( value >> 48 );
                bytes[0] = ( byte ) ( value >> 56 );
            }
        }
        else
        {
            // On special case : 0x80000000
            if ( value == 0x8000000000000000L )
            {
                bytes = new byte[8];
                bytes[7] = ( byte ) 0x00;
                bytes[6] = ( byte ) 0x00;
                bytes[5] = ( byte ) 0x00;
                bytes[4] = ( byte ) 0x00;
                bytes[3] = ( byte ) 0x00;
                bytes[2] = ( byte ) 0x00;
                bytes[1] = ( byte ) 0x00;
                bytes[0] = ( byte ) 0x80;
            }
            else
            {
                // We have to compute the complement, and add 1
                if ( value >= 0xFFFFFFFFFFFFFF80L )
                {
                    bytes = new byte[1];
                    bytes[0] = ( byte ) value;
                }
                else if ( value >= 0xFFFFFFFFFFFF8000L )
                {
                    bytes = new byte[2];
                    bytes[1] = ( byte ) ( value );
                    bytes[0] = ( byte ) ( value >> 8 );
                }
                else if ( value >= 0xFFFFFFFFFF800000L )
                {
                    bytes = new byte[3];
                    bytes[2] = ( byte ) value;
                    bytes[1] = ( byte ) ( value >> 8 );
                    bytes[0] = ( byte ) ( value >> 16 );
                }
                else if ( value >= 0xFFFFFFFF80000000L )
                {
                    bytes = new byte[4];
                    bytes[3] = ( byte ) value;
                    bytes[2] = ( byte ) ( value >> 8 );
                    bytes[1] = ( byte ) ( value >> 16 );
                    bytes[0] = ( byte ) ( value >> 24 );
                }
                else if ( value >= 0xFFFFFF8000000000L )
                {
                    bytes = new byte[5];
                    bytes[4] = ( byte ) value;
                    bytes[3] = ( byte ) ( value >> 8 );
                    bytes[2] = ( byte ) ( value >> 16 );
                    bytes[1] = ( byte ) ( value >> 24 );
                    bytes[0] = ( byte ) ( value >> 32 );
                }
                else if ( value >= 0xFFFF800000000000L )
                {
                    bytes = new byte[6];
                    bytes[5] = ( byte ) value;
                    bytes[4] = ( byte ) ( value >> 8 );
                    bytes[3] = ( byte ) ( value >> 16 );
                    bytes[2] = ( byte ) ( value >> 24 );
                    bytes[1] = ( byte ) ( value >> 32 );
                    bytes[0] = ( byte ) ( value >> 40 );
                }
                else if ( value >= 0xFF80000000000000L )
                {
                    bytes = new byte[7];
                    bytes[6] = ( byte ) value;
                    bytes[5] = ( byte ) ( value >> 8 );
                    bytes[4] = ( byte ) ( value >> 16 );
                    bytes[3] = ( byte ) ( value >> 24 );
                    bytes[2] = ( byte ) ( value >> 32 );
                    bytes[1] = ( byte ) ( value >> 40 );
                    bytes[0] = ( byte ) ( value >> 48 );
                }
                else
                {
                    bytes = new byte[8];
                    bytes[7] = ( byte ) value;
                    bytes[6] = ( byte ) ( value >> 8 );
                    bytes[5] = ( byte ) ( value >> 16 );
                    bytes[4] = ( byte ) ( value >> 24 );
                    bytes[3] = ( byte ) ( value >> 32 );
                    bytes[2] = ( byte ) ( value >> 40 );
                    bytes[1] = ( byte ) ( value >> 48 );
                    bytes[0] = ( byte ) ( value >> 56 );
                }
            }
        }

        return bytes;
    }


    /**
     * Encode a boolean value
     *
     * @param buffer The PDU in which the value will be put
     * @param bool The boolean to be encoded
     */
    public static void encodeBoolean( Asn1Buffer buffer, boolean bool )
    {
        if ( bool )
        {
            buffer.put( ENCODED_TRUE );
        }
        else
        {
            buffer.put( ENCODED_FALSE );
        }
    }


    /**
     * Encode a boolean value
     *
     * @param buffer The PDU in which the value will be put
     * @param tag the TAG to use
     * @param bool The boolean to be encoded
     */
    public static void encodeBoolean( Asn1Buffer buffer, byte tag, boolean bool )
    {
        if ( bool )
        {
            buffer.put( TRUE_VALUE );
            buffer.put( ( byte ) 0x01 );
            buffer.put( tag );
        }
        else
        {
            buffer.put( FALSE_VALUE );
            buffer.put( ( byte ) 0x01 );
            buffer.put( tag );
        }
    }


    /**
     * Encode an integer value
     *
     * @param buffer The PDU in which the value will be put
     * @param value The integer to be encoded
     */
    public static void encodeInteger( Asn1Buffer buffer, int value )
    {
        buffer.put( getBytes( value ) );
        buffer.put( ( byte ) getNbBytes( value ) );
        buffer.put( UniversalTag.INTEGER.getValue() );
    }


    /**
     * Encode an integer value, with a specific tag
     *
     * @param buffer The PDU in which the value will be put
     * @param tag The tag to use
     * @param value The integer to be encoded
     */
    public static void encodeInteger( Asn1Buffer buffer, byte tag, int value )
    {
        buffer.put( getBytes( value ) );
        buffer.put( ( byte ) getNbBytes( value ) );
        buffer.put( tag );
    }


    /**
     * Encode an integer value
     *
     * @param buffer The PDU in which the value will be put
     * @param value The long to be encoded
     */
    public static void encodeInteger( Asn1Buffer buffer, long value )
    {
        buffer.put( getBytes( value ) );
        buffer.put( ( byte ) getNbBytes( value ) );
        buffer.put( UniversalTag.INTEGER.getValue() );
    }


    /**
     * Encode an integer value, with a specific tag
     *
     * @param buffer The PDU in which the value will be put
     * @param tag The tag to use
     * @param value The long to be encoded
     */
    public static void encodeInteger( Asn1Buffer buffer, byte tag, long value )
    {
        buffer.put( getBytes( value ) );
        buffer.put( ( byte ) getNbBytes( value ) );
        buffer.put( tag );
    }


    /**
     * Encode an OctetString
     *
     * @param buffer The PDU in which the value will be put
     * @param data The byte[] to be encoded
     */
    public static void encodeOctetString( Asn1Buffer buffer, byte[] data )
    {
        if ( Strings.isEmpty( data ) )
        {
            buffer.put( ( byte ) 0 );
        }
        else
        {
            buffer.put( data );
            buffer.put( TLV.getBytes( data.length ) );
        }

        buffer.put( UniversalTag.OCTET_STRING.getValue() );
    }


    /**
     * Encode an OctetString
     *
     * @param buffer The PDU in which the value will be put
     * @param value The String to be encoded
     */
    public static void encodeOctetString( Asn1Buffer buffer, String value )
    {
        if ( Strings.isEmpty( value ) )
        {
            buffer.put( ( byte ) 0 );
        }
        else
        {
            byte[] bytes = Strings.getBytesUtf8Ascii( value );
            buffer.put( bytes );
            buffer.put( TLV.getBytes( bytes.length ) );
        }

        buffer.put( UniversalTag.OCTET_STRING.getValue() );
    }


    /**
     * Encode an OctetString
     *
     * @param buffer The PDU in which the value will be put
     * @param tag The tag to use
     * @param data The OctetString to be encoded
     */
    public static void encodeOctetString( Asn1Buffer buffer, byte tag, byte[] data )
    {
        if ( Strings.isEmpty( data ) )
        {
            buffer.put( ( byte ) 0 );
        }
        else
        {
            buffer.put( data );
            buffer.put( TLV.getBytes( data.length ) );
        }

        buffer.put( tag );
    }


    /**
     * Encode an OctetString
     *
     * @param buffer The PDU in which the value will be put
     * @param tag The tag to use
     * @param value The OctetString to be encoded
     */
    public static void encodeOctetString( Asn1Buffer buffer, byte tag, String value )
    {
        if ( Strings.isEmpty( value ) )
        {
            buffer.put( ( byte ) 0 );
        }
        else
        {
            byte[] bytes = Strings.getBytesUtf8Ascii( value );
            buffer.put( bytes );
            buffer.put( TLV.getBytes( bytes.length ) );
        }

        buffer.put( tag );
    }


    /**
     * Encode a Sequence
     *
     * @param buffer The PDU in which the Sequence will be put
     */
    public static void encodeSequence( Asn1Buffer buffer )
    {
        buffer.put( TLV.getBytes( buffer.getPos() ) );
        buffer.put( UniversalTag.SEQUENCE.getValue() );
    }


    /**
     * Encode a Sequence, with a specific length
     *
     * @param buffer The PDU in which the Sequence will be put
     * @param start The Sequence length
     */
    public static void encodeSequence( Asn1Buffer buffer, int start )
    {
        buffer.put( TLV.getBytes( buffer.getPos() - start ) );
        buffer.put( UniversalTag.SEQUENCE.getValue() );
    }


    /**
     * Encode a Sequence, with a specific tag
     *
     * @param buffer The PDU in which the Sequence will be put
     * @param tag The tag to use
     */
    public static void encodeSequence( Asn1Buffer buffer, byte tag )
    {
        buffer.put( TLV.getBytes( buffer.getPos() ) );
        buffer.put( tag );
    }


    /**
     * Encode a Sequence, with a specific length and tag
     *
     * @param buffer The PDU in which the Sequence will be put
     * @param tag The tag to use
     * @param start The position in the buffer this Sequence starts
     */
    public static void encodeSequence( Asn1Buffer buffer, byte tag, int start )
    {
        buffer.put( TLV.getBytes( buffer.getPos() - start ) );
        buffer.put( tag );
    }


    /**
     * Encode a Set
     *
     * @param buffer The PDU in which the Set will be put
     */
    public static void encodeSet( Asn1Buffer buffer )
    {
        buffer.put( TLV.getBytes( buffer.getPos() ) );
        buffer.put( UniversalTag.SET.getValue() );
    }


    /**
     * Encode a Set, with a specific length
     *
     * @param buffer The PDU in which the Set will be put
     * @param start The Set length
     */
    public static void encodeSet( Asn1Buffer buffer, int start )
    {
        buffer.put( TLV.getBytes( buffer.getPos() - start ) );
        buffer.put( UniversalTag.SET.getValue() );
    }


    /**
     * Encode a Set, with a specific tag
     *
     * @param buffer The PDU in which the value will be put
     * @param tag The tag to use
     */
    public static void encodeSet( Asn1Buffer buffer, byte tag )
    {
        buffer.put( TLV.getBytes( buffer.getPos() ) );
        buffer.put( tag );
    }


    /**
     * Encode a Set, with a specific length and tag
     *
     * @param buffer The PDU in which the set will be put
     * @param tag The tag to use
     * @param start The position in the buffer this Set starts
     */
    public static void encodeSet( Asn1Buffer buffer, byte tag, int start )
    {
        buffer.put( TLV.getBytes( buffer.getPos() - start ) );
        buffer.put( tag );
    }


    /**
     * Encode a String value
     *
     * @param buffer The PDU in which the value will be put
     * @param string The String to be encoded. It is supposed to be UTF-8
     * @throws EncoderException if the PDU in which the value should be encoded is
     * two small
     */
    public static void encode( ByteBuffer buffer, String string ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01300_CANNOT_PUT_PDU_IN_NULL_BUFFER ) );
        }

        try
        {
            buffer.put( UniversalTag.OCTET_STRING.getValue() );

            byte[] value = Asn1StringUtils.getBytesUtf8( string );

            buffer.put( TLV.getBytes( value.length ) );

            if ( value.length != 0 )
            {
                buffer.put( value );
            }
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01301_PDU_BUFFER_SIZE_TOO_SMALL ), boe );
        }
    }


    /**
     * Encode a BIT STRING value
     *
     * @param buffer The PDU in which the value will be put
     * @param bitString The BitString to be encoded.
     * @throws EncoderException if the PDU in which the value should be encoded is
     * two small
     */
    public static void encode( ByteBuffer buffer, BitString bitString ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01300_CANNOT_PUT_PDU_IN_NULL_BUFFER ) );
        }

        try
        {
            buffer.put( UniversalTag.BIT_STRING.getValue() );

            // The BitString length. We add one byte for the unused number
            // of bits
            byte[] bytes = bitString.getData();
            int length = bytes.length;

            buffer.put( TLV.getBytes( length ) );
            buffer.put( bytes );
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01301_PDU_BUFFER_SIZE_TOO_SMALL ), boe );
        }
    }


    /**
     * Encode an OctetString value
     *
     * @param buffer The PDU in which the value will be put
     * @param bytes The bytes to be encoded
     * @throws EncoderException if the PDU in which the value should be encoded is
     * two small
     */
    public static void encode( ByteBuffer buffer, byte[] bytes ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01300_CANNOT_PUT_PDU_IN_NULL_BUFFER ) );
        }

        try
        {
            buffer.put( UniversalTag.OCTET_STRING.getValue() );

            if ( ( bytes == null ) || ( bytes.length == 0 ) )
            {
                buffer.put( ( byte ) 0 );
            }
            else
            {
                buffer.put( TLV.getBytes( bytes.length ) );
                buffer.put( bytes );
            }
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01301_PDU_BUFFER_SIZE_TOO_SMALL ), boe );
        }
    }


    /**
     * Encode an OID value
     *
     * @param buffer The PDU in which the value will be put
     * @param oid The OID to be encoded
     * @throws EncoderException if the PDU in which the value should be encoded is
     * two small
     */
    public static void encode( ByteBuffer buffer, Oid oid ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01300_CANNOT_PUT_PDU_IN_NULL_BUFFER ) );
        }

        try
        {
            buffer.put( UniversalTag.OCTET_STRING.getValue() );
            buffer.put( TLV.getBytes( oid.getEncodedLength() ) );

            if ( oid.getEncodedLength() != 0 )
            {
                oid.writeBytesTo( buffer );
            }
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01301_PDU_BUFFER_SIZE_TOO_SMALL ), boe );
        }
    }


    /**
     * Encode an integer value
     *
     * @param buffer The PDU in which the value will be put
     * @param value The integer to be encoded
     * @throws EncoderException if the PDU in which the value should be encoded is
     * two small
     */
    public static void encode( ByteBuffer buffer, int value ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01300_CANNOT_PUT_PDU_IN_NULL_BUFFER ) );
        }

        try
        {
            buffer.put( UniversalTag.INTEGER.getValue() );
            buffer.put( ( byte ) getNbBytes( value ) );
            buffer.put( getBytes( value ) );
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01301_PDU_BUFFER_SIZE_TOO_SMALL ), boe );
        }
    }


    /**
     * Encode a long value
     *
     * @param buffer The PDU in which the value will be put
     * @param value The long to be encoded
     * @throws EncoderException if the PDU in which the value should be encoded is
     * two small
     */
    public static void encode( ByteBuffer buffer, long value ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01300_CANNOT_PUT_PDU_IN_NULL_BUFFER ) );
        }

        try
        {
            buffer.put( UniversalTag.INTEGER.getValue() );
            buffer.put( ( byte ) getNbBytes( value ) );
            buffer.put( getBytes( value ) );
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01301_PDU_BUFFER_SIZE_TOO_SMALL ), boe );
        }
    }


    /**
     * Encode an integer value
     *
     * @param buffer The PDU in which the value will be put
     * @param tag The tag if it's not an UNIVERSAL one
     * @param value The integer to be encoded
     * @throws EncoderException if the PDU in which the value should be encoded is
     * two small
     */
    public static void encode( ByteBuffer buffer, byte tag, int value ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01300_CANNOT_PUT_PDU_IN_NULL_BUFFER ) );
        }

        try
        {
            buffer.put( tag );
            buffer.put( ( byte ) getNbBytes( value ) );
            buffer.put( getBytes( value ) );
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01301_PDU_BUFFER_SIZE_TOO_SMALL ), boe );
        }
    }


    /**
     * Encode an enumerated value
     *
     * @param buffer The PDU in which the value will be put
     * @param value The integer to be encoded
     */
    public static void encodeEnumerated( Asn1Buffer buffer, int value )
    {
        buffer.put( getBytes( value ) );
        buffer.put( TLV.getBytes( getNbBytes( value ) ) );
        buffer.put( UniversalTag.ENUMERATED.getValue() );
    }


    /**
     * Encode an enumerated value
     *
     * @param buffer The PDU in which the value will be put
     * @param tag The tag to use
     * @param value The integer to be encoded
     */
    public static void encodeEnumerated( Asn1Buffer buffer, byte tag, int value )
    {
        buffer.put( getBytes( value ) );
        buffer.put( TLV.getBytes( getNbBytes( value ) ) );
        buffer.put( tag );
    }


    /**
     * Encode an enumerated value
     *
     * @param buffer The PDU in which the value will be put
     * @param value The integer to be encoded
     * @throws EncoderException if the PDU in which the value should be encoded is
     * two small
     */
    public static void encodeEnumerated( ByteBuffer buffer, int value ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01300_CANNOT_PUT_PDU_IN_NULL_BUFFER ) );
        }

        try
        {
            buffer.put( UniversalTag.ENUMERATED.getValue() );
            buffer.put( TLV.getBytes( getNbBytes( value ) ) );
            buffer.put( getBytes( value ) );
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01301_PDU_BUFFER_SIZE_TOO_SMALL ), boe );
        }
    }


    /**
     * Encode a boolean value
     *
     * @param buffer The PDU in which the value will be put
     * @param bool The boolean to be encoded
     * @throws EncoderException if the PDU in which the value should be encoded is
     * two small
     */
    public static void encode( ByteBuffer buffer, boolean bool ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01300_CANNOT_PUT_PDU_IN_NULL_BUFFER ) );
        }

        try
        {
            if ( bool )
            {
                buffer.put( ENCODED_TRUE );
            }
            else
            {
                buffer.put( ENCODED_FALSE );
            }
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_01301_PDU_BUFFER_SIZE_TOO_SMALL ), boe );
        }
    }


    /**
     * Return a string representing the Value
     *
     * @return A string representing the value
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append( "DATA" );

        if ( data != null )
        {
            sb.append( '[' );
            sb.append( Asn1StringUtils.dumpBytes( data ) );
            sb.append( ']' );
        }
        else
        {
            return "[]";
        }

        return sb.toString();
    }
}
