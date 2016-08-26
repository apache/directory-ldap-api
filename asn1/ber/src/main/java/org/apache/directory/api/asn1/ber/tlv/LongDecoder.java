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


/**
 * Parse and decode a Long value.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class LongDecoder
{
    /** A mask used to get only the necessary bytes */
    private static final long[] MASK = new long[]
        { 0x00000000000000FFL, 0x000000000000FFFFL, 0x0000000000FFFFFFL, 0x00000000FFFFFFFFL, 0x000000FFFFFFFFFFL,
            0x0000FFFFFFFFFFFFL, 0x00FFFFFFFFFFFFFFL, 0xFFFFFFFFFFFFFFFFL };


    private LongDecoder()
    {
    }


    /**
     * Parse a byte buffer and send back an long, controlling that this number
     * is in a specified interval.
     *
     * @param value The byte buffer to parse
     * @param min Lowest value allowed, included
     * @param max Highest value allowed, included
     * @return An integer
     * @throws LongDecoderException Thrown if the byte stream does not contains an integer
     */
    public static long parse( BerValue value, long min, long max ) throws LongDecoderException
    {
        long result = parseLong( value );

        if ( ( result >= min ) && ( result <= max ) )
        {
            return result;
        }
        else
        {
            throw new LongDecoderException( I18n.err( I18n.ERR_00038_VALUE_NOT_IN_RANGE, min, max ) );
        }
    }


    /**
     * Parse a byte buffer and send back an integer
     *
     * @param value The byte buffer to parse
     * @return An integer
     * @throws LongDecoderException Thrown if the byte stream does not contains an integer
     */
    public static long parse( BerValue value ) throws LongDecoderException
    {
        return parseLong( value );
    }
    
    
    /**
     * Helper method used to parse the long. We don't check any minimal or maximal
     * bound.
     * 
     * @param value The value to parse to a long
     * @return The decoded long
     * @throws LongDecoderException If we failed to decode a long
     */
    public static long parseLong( BerValue value ) throws LongDecoderException
    {
        long result = 0;

        byte[] bytes = value.getData();

        if ( ( bytes == null ) || ( bytes.length == 0 ) )
        {
            throw new LongDecoderException( I18n.err( I18n.ERR_00039_0_BYTES_LONG_LONG ) );
        }

        if ( bytes.length > 8 )
        {
            throw new LongDecoderException( I18n.err( I18n.ERR_00039_0_BYTES_LONG_LONG ) );
        }

        for ( int i = 0; ( i < bytes.length ) && ( i < 9 ); i++ )
        {
            result = ( result << 8 ) | ( bytes[i] & 0x00FF );
        }

        if ( ( bytes[0] & 0x80 ) == 0x80 )
        {
            result = -( ( ( ~result ) + 1 ) & MASK[bytes.length - 1] );
        }
        
        return result;
    }
}
