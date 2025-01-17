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


import org.apache.directory.api.asn1.util.Asn1StringUtils;


/**
 * This class is used to store Tags, Lengths and Values decoded from a PDU.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class TLV
{
    /** The current Tag being processed */
    private byte tag;

    /** The current Length being processed */
    private int length;

    /** The number of byte to store the Length being processed */
    private int lengthNbBytes;

    /** The number of length's bytes currently read */
    private int lengthBytesRead;

    /** The current Value being processed */
    private BerValue value;

    /** An identity for the TLV. It store the TLV hashCode */
    private int id;

    /**
     * Reference the TLV which contains the current TLV, if any. As the
     * enclosing TLV of a PDU does not have parent, it can be null in this case.
     * Otherwise, it must point to a constructed TLV
     */
    private TLV parent;

    /**
     * The expected length of the TLV's elements, if the current TLV is a
     * constructed TLV.
     */
    private int expectedLength;

    /** tag flag for the primitive/constructed bit - 0010 0000 - 0x20 */
    public static final byte CONSTRUCTED_FLAG = 0x20;

    /** mask to get the type class value */
    public static final byte TYPE_CLASS_MASK = ( byte ) 0xC0;

    /** value for the universal type class */
    public static final byte TYPE_CLASS_UNIVERSAL = 0x00;

    /** tag mask for the short tag format - 0001 1111 - 0x1F */
    public static final int SHORT_MASK = 0x1F;

    /** A mask to get the Length form */
    public static final int LENGTH_LONG_FORM = 0x0080;

    /** Value of the reserved extension */
    public static final int LENGTH_EXTENSION_RESERVED = 0x7F;

    /** A mask to get the long form value */
    public static final int LENGTH_SHORT_MASK = 0x007F;

    /** A speedup for single bytes length */
    private static final byte[][] ONE_BYTE = new byte[128][];

    // Initialize an array of byte[] used for encoding lengths below 128
    static
    {
        for ( int i = 0; i < 128; i++ )
        {
            ONE_BYTE[i] = new byte[1];
            ONE_BYTE[i][0] = ( byte ) i;
        }
    }


    /**
     * Creates a new TLV object.
     * 
     * @param id the TLV's id
     */
    public TLV( int id )
    {
        tag = 0;
        length = 0;
        lengthNbBytes = 0;
        value = new BerValue();
        this.id = id;

        expectedLength = 0;
    }


    /**
     * Checks to see if the tag is constructed.
     * 
     * @param tag the TLV's tag
     * @return true if constructed, false if primitive
     */
    public static boolean isConstructed( byte tag )
    {
        return ( tag & CONSTRUCTED_FLAG ) != 0;
    }


    /**
     * Checks to see if the current tlv's tag is constructed.
     * 
     * @return true if constructed, false if primitive
     */
    public boolean isConstructed()
    {
        return ( tag & CONSTRUCTED_FLAG ) != 0;
    }


    /**
     * Checks to see if the tag represented by this Tag is primitive or
     * constructed.
     * 
     * @param tag the tag to be checked
     * @return true if it is primitive, false if it is constructed
     */
    public static boolean isPrimitive( byte tag )
    {
        return ( tag & CONSTRUCTED_FLAG ) == 0;
    }


    /**
     * Tells if the tag is Universal or not
     * 
     * @param tag the tag to be checked
     * @return true if it is primitive, false if it is constructed
     */
    public static boolean isUniversal( byte tag )
    {
        return ( tag & TYPE_CLASS_MASK ) == TYPE_CLASS_UNIVERSAL;
    }


    /**
     * Reset the TLV, so it can be reused for the next PDU decoding.
     */
    public void reset()
    {
        tag = 0;
        length = 0;
        lengthNbBytes = 0;
        value.reset();

        expectedLength = 0;
    }


    /**
     * Get the TLV's tag
     * 
     * @return Returns the tag.
     */
    public byte getTag()
    {
        return tag;
    }


    /**
     * Set a tag value for this TLV.
     * 
     * @param tag the tag field for this TLV.
     */
    public void setTag( byte tag )
    {
        this.tag = tag;
    }


    /**
     * Get the TLV's value part
     * 
     * @return Returns the value.
     */
    public BerValue getValue()
    {
        return value;
    }


    /**
     * The TLV size is calculated by adding the Tag's size, the Length's size
     * and the Value's length, if any.
     * 
     * @return Returns the size of the TLV.
     */
    public int getSize()
    {
        return 1 + lengthNbBytes + length;
    }


    /**
     * Utility function that return the number of bytes necessary to store the
     * length
     * 
     * @param length The length to store in a byte array
     * @return The number of bytes necessary to store the length.
     * @see <a href="http://en.wikipedia.org/wiki/X.690#Length_Octets">X.690</a>
     */
    public static int getNbBytes( int length )
    {
        if ( length >= 0 )
        {
            if ( length < 128 )
            {
                return 1;
            }
            else if ( length < 256 )
            {
                return 2;
            }
            else if ( length < 65536 )
            {
                return 3;
            }
            else if ( length < 16777216 )
            {
                return 4;
            }
            else
            {
                return 5;
            }
        }
        else
        {
            return 5;
        }
    }


    /**
     * Utility function that return a byte array representing the length
     * 
     * @param length The length to store in a byte array
     * @return The byte array representing the length.
     */
    public static byte[] getBytes( int length )
    {
        if ( length >= 0 )
        {
            if ( length < 128 )
            {
                return ONE_BYTE[length];
            }
            else
            {
                byte[] bytes = new byte[getNbBytes( length )];

                if ( length < 256 )
                {
                    bytes[0] = ( byte ) 0x81;
                    bytes[1] = ( byte ) length;
                }
                else if ( length < 65536 )
                {
                    bytes[0] = ( byte ) 0x82;
                    bytes[1] = ( byte ) ( length >> 8 );
                    bytes[2] = ( byte ) ( length & 0x00FF );
                }
                else if ( length < 16777216 )
                {
                    bytes[0] = ( byte ) 0x83;
                    bytes[1] = ( byte ) ( length >> 16 );
                    bytes[2] = ( byte ) ( ( length >> 8 ) & 0x00FF );
                    bytes[3] = ( byte ) ( length & 0x00FF );
                }
                else
                {
                    bytes[0] = ( byte ) 0x84;
                    bytes[1] = ( byte ) ( length >> 24 );
                    bytes[2] = ( byte ) ( ( length >> 16 ) & 0x00FF );
                    bytes[3] = ( byte ) ( ( length >> 8 ) & 0x00FF );
                    bytes[4] = ( byte ) ( length & 0x00FF );
                }

                return bytes;
            }
        }
        else
        {
            byte[] bytes = new byte[getNbBytes( length )];

            bytes[0] = ( byte ) 0x84;
            bytes[1] = ( byte ) ( length >> 24 );
            bytes[2] = ( byte ) ( ( length >> 16 ) & 0x00FF );
            bytes[3] = ( byte ) ( ( length >> 8 ) & 0x00FF );
            bytes[4] = ( byte ) ( length & 0x00FF );

            return bytes;
        }
    }


    /**
     * Get the TLV's parent
     * 
     * @return The parent.
     */
    public TLV getParent()
    {
        return parent;
    }


    /**
     * Set the TLV's parent
     * 
     * @param parent The parent to set.
     */
    public void setParent( TLV parent )
    {
        this.parent = parent;
    }


    /**
     * Get the TLV expected length.
     * 
     * @return The expectedLength.
     */
    public int getExpectedLength()
    {
        return expectedLength;
    }


    /**
     * Set the new expected length of the current TLV.
     * 
     * @param expectedLength The expectedLength to set.
     */
    public void setExpectedLength( int expectedLength )
    {
        this.expectedLength = expectedLength;
    }


    /**
     * Get the TLV's length
     * 
     * @return The number of bytes necessary to store the TLV's length
     */
    public int getLengthNbBytes()
    {
        return lengthNbBytes;
    }


    /**
     * Set the number of bytes we should use to store the TLV's length.
     * 
     * @param lengthNbBytes The number of bytes necessary to store the TLV's length
     */
    public void setLengthNbBytes( int lengthNbBytes )
    {
        this.lengthNbBytes = lengthNbBytes;
    }


    /**
     * Get the TLV's length
     * 
     * @return the TLV's length
     */
    public int getLength()
    {
        return length;
    }


    /**
     * Set the TLV's length
     *
     * @param length the TLV's length
     */
    public void setLength( int length )
    {
        this.length = length;
    }


    /**
     * Get the already read bytes
     * 
     * @return The currently read TLV's length bytes
     */
    public int getLengthBytesRead()
    {
        return lengthBytesRead;
    }


    /**
     * Set the currently read TLV's length bytes.
     * 
     * @param lengthBytesRead the currently read TLV's length bytes
     */
    public void setLengthBytesRead( int lengthBytesRead )
    {
        this.lengthBytesRead = lengthBytesRead;
    }


    /**
     * Increment the number of bytes read for this TLV
     */
    public void incLengthBytesRead()
    {
        lengthBytesRead++;
    }


    /**
     * Get the TLV's ID
     * 
     * @return The TLV's ID
     */
    public int getId()
    {
        return id;
    }


    /**
     * Get a String representation of the TLV
     * 
     * @return A String
     */
    @Override
    public String toString()
    {

        StringBuilder sb = new StringBuilder();

        sb.append( "TLV[ " );
        sb.append( Asn1StringUtils.dumpByte( tag ) ).append( ", " );
        sb.append( "length:" ).append( length ).append( ", " );
        sb.append( "expected:" ).append( expectedLength ).append( ", " );
        sb.append( value.toString() );
        sb.append( "]" );

        return sb.toString();
    }
}
