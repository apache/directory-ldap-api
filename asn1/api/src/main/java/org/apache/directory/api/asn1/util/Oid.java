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
package org.apache.directory.api.asn1.util;


import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Arrays;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.i18n.I18n;


/**
 * An immutable representation of an object identifier that provides conversion 
 * between their <code>String</code>, and encoded <code>byte[]</code> 
 * representations.
 * 
 * <p> The encoding of OID values is performed according to 
 * <a href='http://www.itu.int/rec/T-REC-X.690/en'>itu X.690</a> section 8.19.
 * Specifically:</p>
 * 
 * <p><b>8.19.2</b> The contents octets shall be an (ordered) list of encodings
 * of subidentifiers (see 8.19.3 and 8.19.4) concatenated together. Each 
 * subidentifier is represented as a series of (one or more) octets. Bit 8 of 
 * each octet indicates whether it is the last in the series: bit 8 of the last 
 * octet is zero; bit 8 of each preceding octet is one. Bits 7 to 1 of the 
 * octets in the series collectively encode the subidentifier. Conceptually, 
 * these groups of bits are concatenated to form an unsigned binary number whose 
 * most significant bit is bit 7 of the first octet and whose least significant 
 * bit is bit 1 of the last octet. The subidentifier shall be encoded in the 
 * fewest possible octets, that is, the leading octet of the subidentifier shall 
 * not have the value 0x80. </p>
 * 
 * <p><b>8.19.3</b> The number of subidentifiers (N) shall be one less than the 
 * number of object identifier components in the object identifier value being 
 * encoded.</p>
 * 
 * <p><b>8.19.4</b> The numerical value of the first subidentifier is derived 
 * from the values of the first two object identifier components in the object 
 * identifier value being encoded, using the formula:
 * <br><code>(X*40) + Y</code><br> 
 * where X is the value of the first object identifier component and Y is the 
 * value of the second object identifier component. <i>NOTE – This packing of 
 * the first two object identifier components recognizes that only three values 
 * are allocated from the root node, and at most 39 subsequent values from nodes 
 * reached by X = 0 and X = 1.</i></p>
 * 
 * <p>For example, the OID "2.12.3456.7" would be turned into a list of 3 values:
 * <code>[((2*40)+12), 3456, 7]</code>. The first of which, 
 * <code>92</code>, would be encoded as the bytes <code>0x5C</code>, the second 
 * would be <code>[0x9B, 0x00]</code>, and the third as <code>0x07</code>
 * giving the final encoding <code>[0x5C, 0x9B, 0x00, 0x07]</code>.</p>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class Oid
{
    /** A byte[] representation of an OID */
    private byte[] oidBytes;
    
    /** The OID as a String */
    private String oidString;
    
    private static final BigInteger JOINT_ISO_ITU_T = new BigInteger( "80" );
    
    /**
     * The OID FSA states. We have the following Finite State Automaton :
     * 
     * <pre>
     * (Start) --['0','1']--> (A)
     * (start) --['2']--> (F)
     * 
     * (A) --['.']--> (B)
     * 
     * (B) --['0']--> (D)
     * (B) --['1'..'3']--> (C)
     * (B) --['4'..'9']--> (E)
     * 
     * (C) --[]--> (End)
     * (C) --['.']--> (K)
     * (C) --['0'..'9']--> (E)
     * 
     * (D) --[]--> (End)
     * (D) --['.']--> (K)
     * 
     * (E) --[]--> (End)
     * (E) --['.']--> (K)
     * 
     * (F) --['.']--> (G)
     * 
     * (G) --['0']--> (I)
     * (G) --['1'..'9']--> (H)
     *
     * (H) --[]--> (End)
     * (H) --['.']--> (K)
     * (H) --['0'..'9']--> (J)
     * 
     * (I) --[]--> (End)
     * (I) --['.']--> (K)
     *
     * (J) --[]--> (End)
     * (J) --['.']--> (K)
     * (J) --['0'..'9']--> (J)
     * 
     * (K) --['0']--> (M) 
     * (K) --['1'..'9']--> (L)
     * 
     * (L) --[]--> (End)
     * (L) --['.']--> (K)
     * (L) --['0'..'9']--> (L)
     * 
     * (M) --[]--> (End)
     * (M) --['.']--> (K)
     * </pre>
     */
    private enum OidFSAState 
    {
        START,
        STATE_A,
        STATE_B,
        STATE_C,
        STATE_D,
        STATE_E,
        STATE_F,
        STATE_G,
        STATE_H,
        STATE_I,
        STATE_J,
        STATE_K,
        STATE_L,
        STATE_M,
    }


    /**
     * Creates a new instance of Oid.
     *
     * @param oidString The OID as a String
     * @param oidBytes The OID as a byte[]
     */
    private Oid( String oidString, byte[] oidBytes )
    {
        this.oidString = oidString;
        this.oidBytes = new byte[oidBytes.length];
        System.arraycopy( oidBytes, 0, this.oidBytes, 0, oidBytes.length );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals( Object other )
    {
        return ( other instanceof Oid )
            && oidString.equals( ( ( Oid ) other ).oidString );
    }


    /**
     * Decodes an OID from a <code>byte[]</code>.
     * 
     * @param oidBytes The encoded<code>byte[]</code>
     * @return A new Oid
     * @throws DecoderException When the OID is not valid
     */
    public static Oid fromBytes( byte[] oidBytes ) throws DecoderException
    {
        if ( ( oidBytes == null ) || ( oidBytes.length < 1 ) )
        {
            throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, Arrays.toString( oidBytes ) ) );
        }

        StringBuilder builder = new StringBuilder();
        long value = 0;
        int valStart = 0;
        int valLength = 0;
        boolean firstArc = true;
        
        for ( int i = 0; i < oidBytes.length; i++ )
        {
            value |= oidBytes[i] & 0x7F;

            if ( oidBytes[i] < 0 )
            {
                // leading 1, so value continues
                value = value << 7;
                valLength++;
            }
            else
            {
                valLength++;
                
                if ( valLength > 8 )
                {
                    // Above 9 bytes, we won't be able to store the value in a long...
                    // Compute the number of necessary bytes
                    int nbBytes = valLength * 7 / 8;
                    
                    if ( valLength % 7 != 0 )
                    {
                        nbBytes++;
                    }
                    
                    byte[] result = new byte[nbBytes];
                    
                    // Now iterate on the incoming bytes
                    int pos = nbBytes - 1;
                    int valEnd = valStart + valLength - 1;
                    int j = 0;
                    
                    while ( j < valLength - 8 )
                    {
                        result[pos--] = ( byte ) ( ( oidBytes[valEnd - j - 1] << 7 ) | ( oidBytes[valEnd - j] & 0x7F ) );
                        result[pos--] = ( byte ) ( ( oidBytes[valEnd - j - 2] << 6 ) | ( ( oidBytes[valEnd - j - 1] & 0x7E ) >> 1 ) );
                        result[pos--] = ( byte ) ( ( oidBytes[valEnd - j - 3] << 5 ) | ( ( oidBytes[valEnd - j - 2] & 0x7C ) >> 2 ) );
                        result[pos--] = ( byte ) ( ( oidBytes[valEnd - j - 4] << 4 ) | ( ( oidBytes[valEnd - j - 3] & 0x78 ) >> 3 ) );
                        result[pos--] = ( byte ) ( ( oidBytes[valEnd - j - 5] << 3 ) | ( ( oidBytes[valEnd - j - 4] & 0x70 ) >> 4 ) );
                        result[pos--] = ( byte ) ( ( oidBytes[valEnd - j - 6] << 2 ) | ( ( oidBytes[valEnd - j - 5] & 0x60 ) >> 5 ) );
                        result[pos--] = ( byte ) ( ( oidBytes[valEnd - j - 7] << 1 ) | ( ( oidBytes[valEnd - j - 6] & 0x40 ) >> 6 ) );
                        j += 8;
                    }
                    
                    switch ( valLength - j )
                    {
                        case 7 :
                            result[pos--] = ( byte ) ( ( oidBytes[5] << 7 ) | ( oidBytes[6] & 0x7F ) );
                            result[pos--] = ( byte ) ( ( oidBytes[4] << 6 ) | ( ( oidBytes[5] & 0x7E ) >> 1 ) );
                            result[pos--] = ( byte ) ( ( oidBytes[3] << 5 ) | ( ( oidBytes[4] & 0x7C ) >> 2 ) );
                            result[pos--] = ( byte ) ( ( oidBytes[2] << 4 ) | ( ( oidBytes[3] & 0x78 ) >> 3 ) );
                            result[pos--] = ( byte ) ( ( oidBytes[1] << 3 ) | ( ( oidBytes[2] & 0x70 ) >> 4 ) );
                            result[pos--] = ( byte ) ( ( oidBytes[0] << 2 ) | ( ( oidBytes[1] & 0x60 ) >> 5 ) );
                            result[pos] = ( byte ) ( ( oidBytes[0] & 0x40 ) >> 6 );
                            break;
                            
                        case 6 :
                            result[pos--] = ( byte ) ( ( oidBytes[4] << 7 ) | ( oidBytes[5] & 0x7F ) );
                            result[pos--] = ( byte ) ( ( oidBytes[3] << 6 ) | ( ( oidBytes[4] & 0x7E ) >> 1 ) );
                            result[pos--] = ( byte ) ( ( oidBytes[2] << 5 ) | ( ( oidBytes[3] & 0x7C ) >> 2 ) );
                            result[pos--] = ( byte ) ( ( oidBytes[1] << 4 ) | ( ( oidBytes[2] & 0x78 ) >> 3 ) );
                            result[pos--] = ( byte ) ( ( oidBytes[0] << 3 ) | ( ( oidBytes[1] & 0x70 ) >> 4 ) );
                            result[pos] = ( byte ) ( ( oidBytes[0] & 0x60 ) >> 5 );
                            break;

                        case 5 :
                            result[pos--] = ( byte ) ( ( oidBytes[3] << 7 ) | ( oidBytes[4] & 0x7F ) );
                            result[pos--] = ( byte ) ( ( oidBytes[2] << 6 ) | ( ( oidBytes[3] & 0x7E ) >> 1 ) );
                            result[pos--] = ( byte ) ( ( oidBytes[1] << 5 ) | ( ( oidBytes[2] & 0x7C ) >> 2 ) );
                            result[pos--] = ( byte ) ( ( oidBytes[0] << 4 ) | ( ( oidBytes[1] & 0x78 ) >> 3 ) );
                            result[pos] = ( byte ) ( ( oidBytes[0] & 0x70 ) >> 4 );
                            break;
                            
                        case 4 :
                            result[pos--] = ( byte ) ( ( oidBytes[2] << 7 ) | ( oidBytes[3] & 0x7F ) );
                            result[pos--] = ( byte ) ( ( oidBytes[1] << 6 ) | ( ( oidBytes[2] & 0x7E ) >> 1 ) );
                            result[pos--] = ( byte ) ( ( oidBytes[0] << 5 ) | ( ( oidBytes[1] & 0x7C ) >> 2 ) );
                            result[pos] = ( byte ) ( ( oidBytes[0] & 0x78 ) >> 3 );
                            break;
                            
                        case 3 :
                            result[pos--] = ( byte ) ( ( oidBytes[1] << 7 ) | ( oidBytes[2] & 0x7F ) );
                            result[pos--] = ( byte ) ( ( oidBytes[0] << 6 ) | ( ( oidBytes[1] & 0x7E ) >> 1 ) );
                            result[pos] = ( byte ) ( ( oidBytes[0] & 0x7C ) >> 2 );
                            break;

                        case 2 :
                            result[pos--] = ( byte ) ( ( oidBytes[0] << 7 ) | ( oidBytes[1] & 0x7F ) );
                            result[pos] = ( byte ) ( ( oidBytes[0] & 0x7E ) >> 1 );
                            break;
                            
                        case 1 :
                            result[pos] = ( byte ) ( oidBytes[0] & 0x7F );
                            break;
                            
                        default :
                            // Exist to please checkstyle...
                            break;
                    }
                    
                    BigInteger bigInteger;
                    
                    if ( ( result[0] & 0x80 ) == 0x80 )
                    {
                        byte[] newResult = new byte[result.length + 1];
                        System.arraycopy( result, 0, newResult, 1, result.length );
                        result = newResult;
                    }
                    
                    bigInteger = new BigInteger( result );
                    
                    if ( firstArc )
                    {
                        // This is a joint-iso-itu-t(2) arc
                        bigInteger = bigInteger.subtract( JOINT_ISO_ITU_T );
                        builder.append( '2' );
                    }
                    
                    builder.append( '.' ).append( bigInteger.toString() );
                }
                else
                {
                    // value completed
                    if ( firstArc )
                    {
                        // first value special processing
                        if ( value >= 80 )
                        {
                            // starts with 2
                            builder.append( '2' );
                            value = value - 80;
                        }
                        else
                        {
                            // starts with 0 or 1
                            long one = value / 40;
                            long two = value % 40;
    
                            if ( ( one < 0 ) || ( one > 2 ) || ( two < 0 ) || ( ( one < 2 ) && ( two > 39 ) ) )
                            {
                                throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID,
                                    Arrays.toString( oidBytes ) ) );
                            }
    
                            if ( one < 2 )
                            {
                                builder.append( one );
                                value = two;
                            }
                        }
                        
                        firstArc = false;
                    }
    
                    // normal processing
                    builder.append( '.' ).append( value );
                }
                
                valStart = i;
                valLength = 0;
                value = 0;
            }
        }
    
        return new Oid( builder.toString(), oidBytes );
    }


    /**
     * Process state A
     * <pre>
     * (Start) --['0','1']--> (A)
     * (start) --['2']--> (F)
     * </pre>
     */
    private static OidFSAState processStateStart( String oid, byte[] buffer, int pos ) throws DecoderException
    {
        char c = oid.charAt( pos );
        
        switch ( c )
        {
            case '0' :
            case '1' :
                buffer[0] = ( byte ) ( ( c - '0' ) * 40 );
                return OidFSAState.STATE_A;
                
            case '2' :
                return OidFSAState.STATE_F;
                
            default :
                // This is an error
                throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "Should start with 0, 1 or 2" ) );
        }
    }
    
    
    /**
     * Process state B
     * <pre>
     * (A) --['.']--> (B)
     * </pre>
     */
    private static OidFSAState processStateA( String oid, int pos ) throws DecoderException
    {
        if ( oid.charAt( pos ) != '.' )
        {
            // Expecting a Dot here
            throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "a '.' is expected" ) );
        }
        
        return OidFSAState.STATE_B;
    }
    
    
    /**
     * Process state B
     * <pre>
     * (B) --['0']--> (D)
     * (B) --['1'..'3']--> (C)
     * (B) --['4'..'9']--> (E)
     * </pre>
     */
    private static OidFSAState processStateB( String oid, byte[] buffer, int pos ) throws DecoderException
    {
        char c = oid.charAt( pos );
        
        switch ( c )
        {
            case '0' :
                return OidFSAState.STATE_D;
                
            case '1' :
            case '2' :
            case '3' :
                // We may have a second digit. Atm, store the current one in the second psotion
                buffer[1] = ( byte ) ( c - '0' );
                
                return  OidFSAState.STATE_C;
                
            case '4' :
            case '5' :
            case '6' :
            case '7' :
            case '8' :
            case '9' :
                buffer[0] += ( byte ) ( c - '0' );
                return OidFSAState.STATE_E;
                
            default :
                // Expecting a digit here
                throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "a digit is expected" ) );
        }
    }
    
    
    /**
     * Process state C
     * <pre>
     * (C) --['.']--> (K)
     * (C) --['0'..'9']--> (E)
     * </pre>
     */
    private static OidFSAState processStateC( String oid, byte[] buffer, int pos ) throws DecoderException
    {
        char c = oid.charAt( pos );
        
        switch ( c )
        {
            case '0' :
            case '1' :
            case '2' :
            case '3' :
            case '4' :
            case '5' :
            case '6' :
            case '7' :
            case '8' :
            case '9' :
                buffer[0] += ( byte ) ( buffer[1] * 10 + ( c - '0' ) );
                buffer[1] = 0;
                return OidFSAState.STATE_E;

            case '.' :
                buffer[0] += buffer[1];
                buffer[1] = 0;
                return OidFSAState.STATE_K;
                
            default :
                // Expecting a digit here
                throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "a digit is expected" ) );
        }
    }
    
    
    /**
     * Process state D and E
     * <pre>
     * (D) --['.']--> (K)
     * (E) --['.']--> (K)
     * </pre>
     */
    private static OidFSAState processStateDE( String oid, byte[] buffer, int pos ) throws DecoderException
    {
        char c = oid.charAt( pos );
        
        if ( c != '.' )
        {
            // Expecting a '.' here
            throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "a dot is expected" ) );
        }
        
        // Store the first byte into it
        buffer[0] = ( byte ) ( buffer[0] | buffer[1] );
        buffer[1] = 0;
        
        return OidFSAState.STATE_K;
    }
    
    
    /**
     * Process state F
     * <pre>
     * (F) --['.']--> (G)
     * </pre>
     */
    private static OidFSAState processStateF( String oid, int pos ) throws DecoderException
    {
        if ( oid.charAt( pos ) != '.' )
        {
            // Expecting a Dot here
            throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "a '.' is expected" ) );
        }
        
        return OidFSAState.STATE_G;
    }
    
    
    /**
     * Process state G
     * <pre>
     * (G) --['0']--> (I)
     * (G) --['1'..'9']--> (H)
     * </pre>
     */
    private static OidFSAState processStateG( String oid, byte[] buffer, int pos ) throws DecoderException
    {
        char c = oid.charAt( pos );
        
        switch ( c )
        {
            case '0' :
                buffer[0] = ( byte ) 80;
                return OidFSAState.STATE_I;
                
            case '1' :
            case '2' :
            case '3' :
            case '4' :
            case '5' :
            case '6' :
            case '7' :
            case '8' :
            case '9' :
                // Store the read digit in the second position in the buffer
                buffer[0] = ( byte ) ( c - '0' );
                return OidFSAState.STATE_H;

            default :
                // Expecting a digit here
                throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "a digit is expected" ) );
        }
    }
    
    
    /**
     * Process state H
     * <pre>
     * (H) --['.']--> (K)
     * (H) --['0'..'9']--> (J)
     * </pre>
     */
    private static OidFSAState processStateH( String oid, byte[] buffer, int pos ) throws DecoderException
    {
        char c = oid.charAt( pos );
        
        switch ( c )
        {
            case '0' :
            case '1' :
            case '2' :
            case '3' :
            case '4' :
            case '5' :
            case '6' :
            case '7' :
            case '8' :
            case '9' :
                // Store the read digit in the first position in the buffer
                buffer[1] = ( byte ) ( c - '0' );
                return OidFSAState.STATE_J;

            case '.' :
                // The first 2 arcs are single digit, we can collapse them in one byte.
                buffer[0] = ( byte ) ( 80 + buffer[0] );
                
                return OidFSAState.STATE_K;
                
            default :
                // Expecting a digit here
                throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "a digit is expected" ) );
        }
    }
    
    
    /**
     * Process state I
     * <pre>
     * (I) --['.']--> (K)
     * </pre>
     */
    private static OidFSAState processStateI( String oid, byte[] buffer, int pos ) throws DecoderException
    {
        char c = oid.charAt( pos );
        
        if ( c == '.' )
        {
            // The first 2 arcs are single digit, we can collapse them in one byte.
            buffer[0] = ( byte ) ( 80 + buffer[1] );
            
            return OidFSAState.STATE_K;
        }
        else
        {
            // Expecting a digit here
            throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "a digit is expected" ) );
        }
    }
    
    
    /**
     * Process state J
     * <pre>
     * (J) --['.']--> (K)
     * (J) --['0'..'9']--> (J)
     * </pre>
     */
    private static OidFSAState processStateJ( String oid, byte[] buffer, int bufferPos, int pos ) throws DecoderException
    {
        char c = oid.charAt( pos );
        
        switch ( c )
        {
            case '.' :
                return OidFSAState.STATE_K;
                
            case '0' :
            case '1' :
            case '2' :
            case '3' :
            case '4' :
            case '5' :
            case '6' :
            case '7' :
            case '8' :
            case '9' :
                // Store the new digit at the right position in the buffer
                buffer[bufferPos] = ( byte ) ( c - '0' );
                return OidFSAState.STATE_J;
                
            default :
                // Expecting a digit here
                throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "a digit is expected" ) );
        }
    }
    
    
    /**
     * Process state J
     * <pre>
     * (K) --['0']--> (M)
     * (K) --['1'..'9']--> (L)
     * </pre>
     */
    private static OidFSAState processStateK( String oid, byte[] buffer, int bufferPos, int pos ) throws DecoderException
    {
        char c = oid.charAt( pos );
        
        switch ( c )
        {
            case '0' :
                buffer[bufferPos] = 0x00;
                return OidFSAState.STATE_M;
                
            case '1' :
            case '2' :
            case '3' :
            case '4' :
            case '5' :
            case '6' :
            case '7' :
            case '8' :
            case '9' :
                // Store the new digit at the right position in the buffer
                return OidFSAState.STATE_L;
                
            default :
                // Expecting a digit here
                throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "a digit is expected" ) );
        }
    }
    
    
    /**
     * Process state J
     * <pre>
     * (L) --['.']--> (K)
     * (L) --['0'..'9']--> (L)
     * </pre>
     */
    private static OidFSAState processStateL( String oid, byte[] buffer, int bufferPos, int pos ) throws DecoderException
    {
        char c = oid.charAt( pos );
        
        switch ( c )
        {
            case '.' :
                return OidFSAState.STATE_K;
                
            case '0' :
            case '1' :
            case '2' :
            case '3' :
            case '4' :
            case '5' :
            case '6' :
            case '7' :
            case '8' :
            case '9' :
                // Store the new digit at the right position in the buffer
                buffer[bufferPos] = ( byte ) ( c - '0' );
                
                return OidFSAState.STATE_L;
                
            default :
                // Expecting a digit here
                throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "a digit or a dot is expected" ) );
        }
    }

    
    /**
     * Process state J
     * <pre>
     * (M) --['.']--> (K)
     * </pre>
     */
    private static OidFSAState processStateM( String oid, int pos ) throws DecoderException
    {
        char c = oid.charAt( pos );
        
        if ( c == '.' )
        {
                return OidFSAState.STATE_K;
        }
        else
        {
            // Expecting a '.' here
            throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "a '.' is expected" ) );
        }
    }

    
    /**
     * Convert a list of digits to a list of 7 bits bytes. We must start by the end, and we don't
     * know how many bytes we will need, except when we will be done with the conversion.
     */
    private static int convert( String oid, byte[] buffer, int start, int nbDigits, int posBuffer, boolean isJointIsoItuT )
    {
        if ( nbDigits < 3 )
        {
            // Speedup when we have a number in [0..99] : it's guaranteed to be hold
            // by a single byte.
            if ( isJointIsoItuT )
            {
                // Another special case : this is an OID that starts with '2.'
                buffer[0] =  ( byte ) ( 80 + ( oid.charAt( 2 ) - '0' ) * 10 + ( oid.charAt( 3 ) - '0' ) );
                
                if ( buffer[0] < 0 )
                {
                    // Here, we need 2 bytes
                    buffer[1] = ( byte ) ( buffer[0] & 0x007F );
                    buffer[0] = ( byte ) 0x81;
                    
                    return 2;
                }
                else
                {
                    return 1;
                }
            }
            else
            {
                if ( nbDigits == 1 )
                {
                    buffer[posBuffer] = ( byte ) ( oid.charAt( start ) - '0' );
                }
                else
                {
                    buffer[posBuffer] = ( byte ) ( ( oid.charAt( start ) - '0' ) * 10 + ( oid.charAt( start + 1 ) - '0' ) );
                    
                }
                return 1;
            }

        }
        else if ( nbDigits < 19 )
        {
            // The value can be hold in a Long if it's up to 999999999999999999 
            // Convert the String to a long :
            String number = oid.substring( start, start + nbDigits );

            long value = Long.parseLong( number );

            if ( isJointIsoItuT )
            {
                value += 80L;
            }
            
            // Convert the long to a byte array
            if ( ( value & 0xFFFFFFFFFFFFFF80L ) == 0 )
            {
                // The value will be hold in one byte
                buffer[posBuffer] = ( byte ) ( value );
                
                return 1;
            }
            
            if ( ( value & 0xFFFFFFFFFFFFC000L ) == 0 )
            {
                // The value is between 0x80 and 0x3FFF : it will be hold in 2 bytes
                buffer[posBuffer] = ( byte ) ( ( byte ) ( ( value & 0x0000000000003F80L ) >> 7 ) | 0x80 );
                buffer[posBuffer + 1] = ( byte ) ( value & 0x000000000000007FL );
                
                return 2;
            }
            
            if ( ( value & 0xFFFFFFFFFFE00000L ) == 0 )
            {
                // The value is between 0x4000 and 0x1FFFFF : it will be hold in 3 bytes
                buffer[posBuffer] = ( byte ) ( ( byte ) ( ( value & 0x00000000001FC000L ) >> 14 ) | 0x80 );
                buffer[posBuffer + 1] = ( byte ) ( ( byte ) ( ( value & 0x0000000000003F80L ) >> 7 ) | 0x80 );
                buffer[posBuffer + 2] = ( byte ) ( value & 0x000000000000007FL );
                
                return 3;
            }
            
            if ( ( value & 0xFFFFFFFFF0000000L ) == 0 )
            {
                // The value is between 0x200000 and 0xFFFFFFF : it will be hold in 4 bytes
                buffer[posBuffer] = ( byte ) ( ( byte ) ( ( value & 0x000000000FE00000L ) >> 21 ) | 0x80 );
                buffer[posBuffer + 1] = ( byte ) ( ( byte ) ( ( value & 0x00000000001FC000L ) >> 14 ) | 0x80 );
                buffer[posBuffer + 2] = ( byte ) ( ( byte ) ( ( value & 0x0000000000003F80L ) >> 7 ) | 0x80 );
                buffer[posBuffer + 3] = ( byte ) ( value & 0x000000000000007FL );
                
                return 4;
            }

            if ( ( value & 0xFFFFFFF800000000L ) == 0 )
            {
                // The value is between 0x10000000 and 0x7FFFFFFFF : it will be hold in 5 bytes
                buffer[posBuffer] = ( byte ) ( ( byte ) ( ( value & 0x00000007F0000000L ) >> 28 ) | 0x80 );
                buffer[posBuffer + 1] = ( byte ) ( ( byte ) ( ( value & 0x000000000FE00000L ) >> 21 ) | 0x80 );
                buffer[posBuffer + 2] = ( byte ) ( ( byte ) ( ( value & 0x00000000001FC000L ) >> 14 ) | 0x80 );
                buffer[posBuffer + 3] = ( byte ) ( ( byte ) ( ( value & 0x0000000000003F80L ) >> 7 ) | 0x80 );
                buffer[posBuffer + 4] = ( byte ) ( value & 0x000000000000007FL );
                
                return 5;
            }

            if ( ( value & 0xFFFFFC0000000000L ) == 0 )
            {
                // The value is between 0x800000000 and 0x3FFFFFFFFFF : it will be hold in 6 bytes
                buffer[posBuffer] = ( byte ) ( ( byte ) ( ( value & 0x000003F800000000L ) >> 35 ) | 0x80 );
                buffer[posBuffer + 1] = ( byte ) ( ( byte ) ( ( value & 0x00000007F0000000L ) >> 28 ) | 0x80 );
                buffer[posBuffer + 2] = ( byte ) ( ( byte ) ( ( value & 0x000000000FE00000L ) >> 21 ) | 0x80 );
                buffer[posBuffer + 3] = ( byte ) ( ( byte ) ( ( value & 0x00000000001FC000L ) >> 14 ) | 0x80 );
                buffer[posBuffer + 4] = ( byte ) ( ( byte ) ( ( value & 0x0000000000003F80L ) >> 7 ) | 0x80 );
                buffer[posBuffer + 5] = ( byte ) ( value & 0x000000000000007FL );
                
                return 6;
            }

            if ( ( value & 0xFFFE000000000000L ) == 0 )
            {
                // The value is between 0x40000000000 and 0x1FFFFFFFFFFFF : it will be hold in 7 bytes
                buffer[posBuffer] = ( byte ) ( ( byte ) ( ( value & 0x0001FC0000000000L ) >> 42 ) | 0x80 );
                buffer[posBuffer + 1] = ( byte ) ( ( byte ) ( ( value & 0x000003F800000000L ) >> 35 ) | 0x80 );
                buffer[posBuffer + 2] = ( byte ) ( ( byte ) ( ( value & 0x00000007F0000000L ) >> 28 ) | 0x80 );
                buffer[posBuffer + 3] = ( byte ) ( ( byte ) ( ( value & 0x000000000FE00000L ) >> 21 ) | 0x80 );
                buffer[posBuffer + 4] = ( byte ) ( ( byte ) ( ( value & 0x00000000001FC000L ) >> 14 ) | 0x80 );
                buffer[posBuffer + 5] = ( byte ) ( ( byte ) ( ( value & 0x0000000000003F80L ) >> 7 ) | 0x80 );
                buffer[posBuffer + 6] = ( byte ) ( value & 0x000000000000007FL );
                
                return 7;
            }

            if ( ( value & 0xFF00000000000000L ) == 0 )
            {
                // The value is between 0x2000000000000 and 0xFF000000000000 : it will be hold in 8 bytes
                buffer[posBuffer] = ( byte ) ( ( byte ) ( ( value & 0x00FE000000000000L ) >> 49 ) | 0x80 );
                buffer[posBuffer + 1] = ( byte ) ( ( byte ) ( ( value & 0x0001FC0000000000L ) >> 42 ) | 0x80 );
                buffer[posBuffer + 2] = ( byte ) ( ( byte ) ( ( value & 0x000003F800000000L ) >> 35 ) | 0x80 );
                buffer[posBuffer + 3] = ( byte ) ( ( byte ) ( ( value & 0x00000007F0000000L ) >> 28 ) | 0x80 );
                buffer[posBuffer + 4] = ( byte ) ( ( byte ) ( ( value & 0x000000000FE00000L ) >> 21 ) | 0x80 );
                buffer[posBuffer + 5] = ( byte ) ( ( byte ) ( ( value & 0x00000000001FC000L ) >> 14 ) | 0x80 );
                buffer[posBuffer + 6] = ( byte ) ( ( byte ) ( ( value & 0x0000000000003F80L ) >> 7 ) | 0x80 );
                buffer[posBuffer + 7] = ( byte ) ( value & 0x000000000000007FL );
                
                return 8;
            }
            else
            {
                // The value is between 0x100000000000000 and 0x7F00000000000000 : it will be hold in 9 bytes
                buffer[posBuffer] = ( byte ) ( ( byte ) ( ( value & 0x7F00000000000000L ) >> 56 ) | 0x80 );
                buffer[posBuffer + 1] = ( byte ) ( ( byte ) ( ( value & 0x00FE000000000000L ) >> 49 ) | 0x80 );
                buffer[posBuffer + 2] = ( byte ) ( ( byte ) ( ( value & 0x0001FC0000000000L ) >> 42 ) | 0x80 );
                buffer[posBuffer + 3] = ( byte ) ( ( byte ) ( ( value & 0x000003F800000000L ) >> 35 ) | 0x80 );
                buffer[posBuffer + 4] = ( byte ) ( ( byte ) ( ( value & 0x00000007F0000000L ) >> 28 ) | 0x80 );
                buffer[posBuffer + 5] = ( byte ) ( ( byte ) ( ( value & 0x000000000FE00000L ) >> 21 ) | 0x80 );
                buffer[posBuffer + 6] = ( byte ) ( ( byte ) ( ( value & 0x00000000001FC000L ) >> 14 ) | 0x80 );
                buffer[posBuffer + 7] = ( byte ) ( ( byte ) ( ( value & 0x0000000000003F80L ) >> 7 ) | 0x80 );
                buffer[posBuffer + 8] = ( byte ) ( value & 0x000000000000007FL );
                
                return 9;
            }
        }
        else
        {
            // The value is bigger than 9999999999999999999, we need to use a BigInteger
            // First, get the number of bytes we need to store the value in base 16
            String number = oid.substring( start, start + nbDigits );
            BigInteger bigInteger = new BigInteger( number );
            
            if ( isJointIsoItuT )
            {
                bigInteger = bigInteger.add( JOINT_ISO_ITU_T );
                posBuffer = 0;
            }
            
            byte[] bytes = bigInteger.toByteArray();
            
            // Now, convert this value to the ASN.1 OID format : we store the value
            // as 7 bits bytes 
            int nbNeededBytes = ( bytes.length * 8 ) / 7;
            
            switch ( ( bytes.length - 1 ) % 7 )
            {
                case 0 :
                    if ( ( bytes[0] & 0x0080 ) != 0 )
                    {
                        nbNeededBytes++;
                    }
                    
                    break;
                    
                case 1 :
                    if ( ( bytes[0] & 0x00C0 ) != 0 )
                    {
                        nbNeededBytes++;
                    }
                    
                    break;
                    
                case 2 :
                    if ( ( bytes[0] & 0x00E0 ) != 0 )
                    {
                        nbNeededBytes++;
                    }
                    
                    break;
                    
                case 3 : 
                    if ( ( bytes[0] & 0x00F0 ) != 0 )
                    {
                        nbNeededBytes++;
                    }
                    
                    break;
                    
                case 4 :
                    if ( ( bytes[0] & 0x00F8 ) != 0 )
                    {
                        nbNeededBytes++;
                    }
                    
                    break;
                    
                case 5 :
                    if ( ( bytes[0] & 0x00FC ) != 0 )
                    {
                        nbNeededBytes++;
                    }
                    
                    break;
                    
                case 6 : 
                    if ( ( bytes[0] & 0x00FE ) != 0 )
                    {
                        nbNeededBytes++;
                    }
                    
                    break;
                    
                default :
                    // Exist to please checkstyle...
                    break;
            }
            
            byte[] converted = new byte[nbNeededBytes];
            
            int posConverted = nbNeededBytes - 1;
            int posBytes = bytes.length - 1;
            int counter = 0;
            byte reminder = 0;
            
            while ( posBytes >= 0 )
            {
                byte newByte = ( byte ) ( ( bytes[posBytes] & 0x00FF ) << counter );
                converted[posConverted] = ( byte ) ( reminder | newByte | 0x0080 );
                reminder = ( byte ) ( ( bytes[posBytes] & 0x00FF ) >> ( 7 - counter ) );
                counter =  ( counter + 1 ) % 8; 
                posConverted--;
                
                if ( counter != 0 )
                {
                    posBytes--;
                }
                else
                {
                    reminder = 0;
                }
            }
            
            converted[nbNeededBytes - 1] &= 0x7F;
            
            // Copy the converted bytes in the buffer
            System.arraycopy( converted, 0, buffer, posBuffer, nbNeededBytes );
            
            return nbNeededBytes;
        }
    }
    
    
    /**
     * Returns an OID object representing <code>oidString</code>.  
     *  
     * @param oidString The string representation of the OID
     * @return A new Oid
     * @throws DecoderException  When the OID is not valid
     */
    public static Oid fromString( String oidString ) throws DecoderException
    {
        if ( ( oidString == null ) || oidString.isEmpty() )
        {
            throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "empty" ) );
        }

        // Create a buffer that is wide enough to contain all the values
        byte[] buffer = new byte[oidString.length()];

        OidFSAState state = OidFSAState.START;
        
        // A counter of chars used for an arc. In 1.2.45345, this counter will be 5 for the '45345' arc.
        int arcNbChars = 0;
        
        // The position in the buffer where we accumulate the result. 
        int bufPos = 0;
        
        // The position in the OID string where we started to read an arc
        int startArc = 0;
        
        // The number of bytes in the resulting OID byte[]
        int nbBytes;
        
        for ( int i = 0; i < oidString.length(); i++ )
        {
            switch ( state )
            {
                case START :
                    // (Start) --['0'..'1']--> (A)
                    // (start) --['2']--> (F)
                    state = processStateStart( oidString, buffer, i );
                    break;
                    
                case STATE_A :
                    // (A) --['.']--> (B)
                    state = processStateA( oidString, i );

                    
                    break;
                    
                case STATE_B :
                    // (B) --['0']--> (D)
                    // (B) --['1'..'3']--> (C)
                    // (B) --['4'..'9']--> (E)
                    state = processStateB( oidString, buffer, i );
                    
                    break;
                    
                case STATE_C :
                    // (C) --['.']--> (K)
                    // (C) --['0'..'9']--> (E)
                    state = processStateC( oidString, buffer, i );

                    // the next arc will be store at position 1 in the buffer
                    bufPos = 1;

                    break;
                    
                case STATE_D :
                    // (D) --['.']--> (K)
                    // Fallthrough
                    
                case STATE_E :
                    // (E) --['.']--> (K)
                    state = processStateDE( oidString, buffer, i );
                    
                    // the next arc will be store at position 1 in teh buffer
                    bufPos = 1;

                    break;
                    
                case STATE_F :
                    // (F) --['.']--> (G)
                    state = processStateF( oidString, i );
                    
                    break;
                    
                case STATE_G :
                    // (G) --['0']--> (I)
                    // (G) --['1'..'9']--> (H)
                    state = processStateG( oidString, buffer, i );
                    arcNbChars = 1;
                    startArc = i;

                    break;

                case STATE_H :
                    // (H) --['.']--> (K)
                    // (H) --['0'..'9']--> (J)
                    state = processStateH( oidString, buffer, i );
                    
                    if ( state == OidFSAState.STATE_J )
                    {
                        // We have already two digits
                        arcNbChars = 2;
                        bufPos = 0;
                    }
                    
                    break;

                case STATE_I :
                    // (I) --['.']--> (K)
                    state = processStateI( oidString, buffer, i );
                    
                    // Set the arc position to buffer[1], we haven't yet accumulated digits.
                    bufPos = 1;
                    
                    break;

                case STATE_J :
                    // (J) --['.']--> (K)
                    // (J) --['0'..'9']--> (J)
                    state = processStateJ( oidString, buffer, arcNbChars + bufPos, i );
                    
                    if ( state == OidFSAState.STATE_J )
                    {
                        // We can increment the number of digit for this arc
                        arcNbChars++;
                    }
                    else
                    {
                        // We are done with the first arc : convert it
                        bufPos += convert( oidString, buffer, bufPos, arcNbChars, 0, true );
                    }
                    
                    break;

                case STATE_K :
                    startArc = i;
                    state = processStateK( oidString, buffer, bufPos, i );
                    
                    if ( state == OidFSAState.STATE_M )
                    { 
                        bufPos++;
                    }
                    else
                    {
                        arcNbChars = 1;
                    }
                    
                    break;

                case STATE_L :
                    state = processStateL( oidString, buffer, arcNbChars + bufPos, i );
                    
                    if ( state == OidFSAState.STATE_L )
                    {
                        arcNbChars++;
                        break;
                    }
                    else
                    {
                        // We are done with the arc : convert it
                        bufPos += convert( oidString, buffer, startArc, arcNbChars, bufPos, false );
                    }

                    break;
                    
                case STATE_M :
                    state = processStateM( oidString, i );
                    break;
                    
                default :
                    // Exist to please checkstyle...
                    break;
            }
        }
        
        // End of the string : check that we are in a correct state for a completion
        // The only valid exit states are :
        // (C) --[]--> (End)
        // (D) --[]--> (End)
        // (E) --[]--> (End)
        // (H) --[]--> (End)
        // (I) --[]--> (End)
        // (J) --[]--> (End)
        // (L) --[]--> (End)
        // (M) --[]--> (End)
        switch ( state )
        {
            case STATE_C :
                // (C) --[]--> (End)
                // fallthrough
                
            case STATE_D :
                // (D) --[]--> (End)
                // fallthrough
                
            case STATE_E :
                // (E) --[]--> (End)
                // fallthrough

            case STATE_H :
                // (H) --[]--> (End)
                // fallthrough
                
            case STATE_I :
                // (I) --[]--> (End)
                byte[] bytes = new byte[1];
                bytes[0] = ( byte ) ( buffer[0] | buffer[1] );

                return new Oid( oidString, bytes );
                
            case STATE_J :
                // (J) --[]--> (End)
                nbBytes = convert( oidString, buffer, 2, arcNbChars, 0, true );
                bytes = new byte[nbBytes];
                System.arraycopy( buffer, 0, bytes, 0, nbBytes );
                
                return new Oid( oidString, bytes );

            case STATE_L :
                bufPos += convert( oidString, buffer, startArc, arcNbChars, bufPos, false );
                bytes = new byte[bufPos];
                System.arraycopy( buffer, 0, bytes, 0, bufPos );
                
                return new Oid( oidString, bytes );
                
            case STATE_M :
                bytes = new byte[bufPos];
                System.arraycopy( buffer, 0, bytes, 0, bufPos );
                
                return new Oid( oidString, bytes );
                
            default :
                // This should never happen...
                throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "Wrong OID" ) );
        }
    }

    
    /**
     * Returns the length of the encoded <code>byte[]</code> representation.
     * 
     * @return The length of the byte[]
     */
    public int getEncodedLength()
    {
        return oidBytes.length;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        return oidString.hashCode();
    }


    /**
     * Returns true if <code>oidString</code> is a valid string representation
     * of an OID.  This method simply calls {@link #fromString(String)} and 
     * returns true if no exception was thrown.  As such, it should not be used 
     * in an attempt to check if a string is a valid OID before calling 
     * {@link #fromString(String)}.
     * 
     * @param oidString The string to test
     * @return True, if <code>oidString</code> is valid
     */
    public static boolean isOid( String oidString )
    {
        try
        {
            Oid.fromString( oidString );

            return true;
        }
        catch ( DecoderException e )
        {
            return false;
        }
    }


    /**
     * Returns the <code>byte[]</code> representation of the OID. The 
     * <code>byte[]</code> that is returned is <i>copied</i> from the internal
     * value so as to preserve the immutability of an OID object.  If the 
     * output of a call to this method is intended to be written to a stream,
     * the {@link #writeBytesTo(OutputStream)} should be used instead as it will
     * avoid creating this copy. 
     * 
     * @return The encoded <code>byte[]</code> representation of the OID.
     */
    public byte[] toBytes()
    {
        return Arrays.copyOf( oidBytes, oidBytes.length );
    }


    /**
     * Returns the string representation of the OID.
     * 
     * @return The string representation of the OID
     */
    @Override
    public String toString()
    {
        return oidString;
    }


    /**
     * Writes the bytes respresenting this OID to the provided buffer.  This 
     * should be used in preference to the {@link #toBytes()} method in order
     * to prevent the creation of copies of the actual <code>byte[]</code>.
     * 
     * @param buffer The buffer to write the bytes into
     */
    public void writeBytesTo( java.nio.ByteBuffer buffer )
    {
        buffer.put( oidBytes );
    }


    /**
     * Writes the bytes respresenting this OID to the provided stream.  This 
     * should be used in preference to the {@link #toBytes()} method in order
     * to prevent the creation of copies of the actual <code>byte[]</code>.
     * 
     * @param outputStream The stream to write the bytes to
     * @throws IOException When we can't write the OID into a Stream
     */
    public void writeBytesTo( OutputStream outputStream ) throws IOException
    {
        outputStream.write( oidBytes );
    }
}
