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
package org.apache.directory.api.asn1.ber.tlv;


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.util.Strings;


/**
 * Parse and decode an Integer value.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class IntegerDecoder
{
    /** A mask used to get only the necessary bytes */
    private static final int[] MASK = new int[]
        { 0x000000FF, 0x0000FFFF, 0x00FFFFFF, 0xFFFFFFFF };


    private IntegerDecoder()
    {
    }


    /**
     * Parse a byte buffer and send back an integer, controlling that this number
     * is in a specified interval.
     *
     * @param value The Value containing the byte[] to parse
     * @param min Lowest value allowed, included
     * @param max Highest value allowed, included
     * @return An integer
     * @throws IntegerDecoderException Thrown if the byte[] does not contains an integer
     */
    public static int parse( BerValue value, int min, int max ) throws IntegerDecoderException
    {
        int result = parseInt( value );

        if ( ( result >= min ) && ( result <= max ) )
        {
            return result;
        }
        else
        {
            throw new IntegerDecoderException( I18n.err( I18n.ERR_00038_VALUE_NOT_IN_RANGE, min, max ) );
        }
    }


    /**
     * Parse a byte buffer and send back an integer
     *
     * @param value The byte buffer to parse
     * @return An integer
     * @throws IntegerDecoderException Thrown if the byte stream does not contains an integer
     */
    public static int parse( BerValue value ) throws IntegerDecoderException
    {
        return parseInt( value );
    }


    /**
     * Helper method used to parse the integer. We don't check any minimal or maximal
     * bound.
     * An BER encoded int can be either positive or negative. It uses the minimum
     * number of byts necessary to encode the value. The high order bit gives the
     * sign of the integer : if it's 1, then it's a negative value, otherwise it's
     * a positive value. Integer with a high order bit set to 1 but prefixed by a 0x00
     * are positive. If the integer is negative, then the 2 complement value is
     * stored<br>
     * Here are a few samples :
     * <ul>
     * <li>0x02 0x01 0x00 : integer 0</li>
     * <li>0x02 0x01 0x01 : integer 1</li>
     * <li>0x02 0x01 0x7F : integer 127</li>
     * <li>0x02 0x01 0x80 : integer -128</li>
     * <li>0x02 0x01 0x81 : integer -127</li>
     * <li>0x02 0x01 0xFF : integer -1</li>
     * <li>0x02 0x02 0x00 0x80 : integer 128</li>
     * <li>0x02 0x02 0x00 0x81 : integer 129</li>
     * <li>0x02 0x02 0x00 0xFF : integer 255</li>
     * </ul>
     * and so on...
     */
    private static int parseInt( BerValue value ) throws IntegerDecoderException
    {
        int result = 0;

        byte[] bytes = value.getData();

        if ( Strings.isEmpty( bytes ) )
        {
            throw new IntegerDecoderException( I18n.err( I18n.ERR_00036_0_BYTES_LONG_INTEGER ) );
        }

        boolean positive = true;

        switch ( bytes.length )
        {
            case 5:
                if ( bytes[0] == 0x00 )
                {
                    if ( ( bytes[1] & ( byte ) 0x80 ) != ( byte ) 0x80 )
                    {
                        throw new IntegerDecoderException( I18n.err( I18n.ERR_00036_0_BYTES_LONG_INTEGER ) );
                    }

                    result = bytes[1] & 0x00FF;
                    result = ( result << 8 ) | ( bytes[2] & 0x00FF );
                    result = ( result << 8 ) | ( bytes[3] & 0x00FF );
                    result = ( result << 8 ) | ( bytes[4] & 0x00FF );
                }
                else
                {
                    throw new IntegerDecoderException( I18n.err( I18n.ERR_00036_0_BYTES_LONG_INTEGER ) );
                }

                break;

            case 4:
                if ( bytes[0] == 0x00 )
                {
                    result = bytes[1] & 0x00FF;
                }
                else
                {
                    result = bytes[0] & 0x00FF;

                    if ( ( bytes[0] & ( byte ) 0x80 ) == ( byte ) 0x80 )
                    {
                        positive = false;
                    }

                    result = ( result << 8 ) | ( bytes[1] & 0x00FF );
                }

                result = ( result << 8 ) | ( bytes[2] & 0x00FF );
                result = ( result << 8 ) | ( bytes[3] & 0x00FF );

                break;

            case 3:
                if ( bytes[0] == 0x00 )
                {
                    result = bytes[1] & 0x00FF;
                }
                else
                {
                    result = bytes[0] & 0x00FF;

                    if ( ( bytes[0] & ( byte ) 0x80 ) == ( byte ) 0x80 )
                    {
                        positive = false;
                    }

                    result = ( result << 8 ) | ( bytes[1] & 0x00FF );
                }

                result = ( result << 8 ) | ( bytes[2] & 0x00FF );

                break;

            case 2:
                if ( bytes[0] == 0x00 )
                {
                    result = bytes[1] & 0x00FF;
                }
                else
                {
                    result = bytes[0] & 0x00FF;

                    if ( ( bytes[0] & ( byte ) 0x80 ) == ( byte ) 0x80 )
                    {
                        positive = false;
                    }

                    result = ( result << 8 ) | ( bytes[1] & 0x00FF );
                }

                break;

            case 1:
                result = ( result << 8 ) | ( bytes[0] & 0x00FF );

                if ( ( bytes[0] & ( byte ) 0x80 ) == ( byte ) 0x80 )
                {
                    positive = false;
                }

                break;

            default:
                throw new IntegerDecoderException( I18n.err( I18n.ERR_00037_ABOVE_4_BYTES_INTEGER ) );
        }

        if ( !positive )
        {
            result = -( ( ( ~result ) + 1 ) & MASK[bytes.length - 1] );
        }

        return result;
    }
}
