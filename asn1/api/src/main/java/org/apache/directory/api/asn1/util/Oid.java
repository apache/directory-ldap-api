package org.apache.directory.api.asn1.util;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Queue;


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
 * <br /><code>(X*40) + Y</code><br /> 
 * where X is the value of the first object identifier component and Y is the 
 * value of the second object identifier component. <i>NOTE – This packing of 
 * the first two object identifier components recognizes that only three values 
 * are allocated from the root node, and at most 39 subsequent values from nodes 
 * reached by X = 0 and X = 1.</i></p>
 * 
 * <p>For example, the OID "2.123456.7" would be turned into a list of 2 values:
 * <code>[((2*80)+123456), 7]</code>.  The first of which, 
 * <code>123536</code>, would be encoded as the bytes 
 * <code>[0x87, 0xC5, 0x10]</code>, the second would be <code>[0x07]</code>,
 * giving the final encoding <code>[0x87, 0xC5, 0x10, 0x07]</code>.</p>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
final public class Oid {
    private byte[] oidBytes;
    private String oidString;
    
    
    private Oid( String oidString, byte[] oidBytes ) {
        this.oidString = oidString;
        this.oidBytes = oidBytes;
    }
    
    
    @Override
    public boolean equals( Object other ) {
        return (other instanceof Oid) 
                && oidString.equals( ((Oid)other).oidString );
    }
    
    
    /**
     * Decodes an OID from a <code>byte[]</code>.
     * 
     * @param oidBytes The encoded<code>byte[]</code>
     * @return A new Oid
     * @throws DecoderException
     */
    public static Oid fromBytes( byte[] oidBytes ) throws DecoderException 
    {
        if ( oidBytes == null || oidBytes.length < 1 ) 
        {
            throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, Arrays.toString( oidBytes ) ) );
        }

        StringBuilder builder = null;
        long value = 0;
        for ( int i = 0; i < oidBytes.length; i++ ) 
        {
            value |= oidBytes[i] & 0x7F;
            if ( oidBytes[i] < 0 ) 
            {
                // leading 1, so value continues
                value = value << 7;
            }
            else 
            {
                // value completed
                if ( builder == null ) {
                    builder = new StringBuilder();
                    // first value special processing
                    if ( value >= 80 ) {
                        // starts with 2
                        builder.append( 2 );
                        value = value - 80;
                    }
                    else {
                        // starts with 0 or 1
                        long one = value/40;
                        long two = value%40;
                        if ( one < 0 || one > 2 || two < 0 || (one < 2 && two > 39) ) 
                        {
                            throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, Arrays.toString( oidBytes ) ) );
                        }
                        if ( one < 2 ) 
                        {
                            builder.append( one );
                            value = two;
                        }
                    }
                }
                
                // normal processing
                builder.append( '.' ).append( value );
                value = 0;
            }
        }
        if ( builder == null ) {
            throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, Arrays.toString( oidBytes ) ) );
        }
        
        return new Oid( builder.toString(), oidBytes );
    }


    /**
     * Returns an OID object representing <code>oidString</code>.  
     *  
     * @param oidString The string representation of the OID
     * @return A new Oid
     * @throws DecoderException 
     */
    public static Oid fromString( String oidString ) throws DecoderException 
    {
        if ( oidString == null || oidString.isEmpty() ) 
        {
            throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, "" ) );
        }

        Queue<Long> segments = new LinkedList<Long>();
        for ( String segment : oidString.split( "\\.", -1 ) ) {
            try
            {
                segments.add( Long.parseLong( segment ) );
            }
            catch ( NumberFormatException e )
            {
                throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, oidString ) );
            }
        }

        // first segment special case
        ByteBuffer buffer = new ByteBuffer();
        Long segmentOne = segments.poll();
        if ( segmentOne == null || segmentOne < 0 || segmentOne > 2 ) 
        {
            throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, oidString ) );
        }

        // second segment special case
        Long segment = segments.poll();
        if ( segment == null || segment < 0 || (segmentOne < 2 && segment > 39) ) 
        {
            throw new DecoderException( I18n.err( I18n.ERR_00033_INVALID_OID, oidString ) );
        }

        buffer.append( (segmentOne * 40) + segment );
        
        // the rest
        while ( (segment = segments.poll()) != null ) 
        {
            buffer.append( segment );
        }

        return new Oid( oidString, buffer.toByteArray() );
    }
    
    
    /**
     * Returns the length of the encoded <code>byte[]</code> representation.
     * 
     * @return The length of the byte[]
     */
    public int getEncodedLength() {
        return oidBytes.length;
    }
    
    
    @Override
    public int hashCode() {
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
        try {
            return Oid.fromString( oidString ) != null;
        }
        catch ( DecoderException e ) {
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
     * @param buffer The buffer to write the bytes to
     * @throws IOException
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
     * @throws IOException
     */
    public void writeBytesTo( OutputStream outputStream ) throws IOException 
    {
        outputStream.write( oidBytes );
    }

    
    // Internal helper class for converting a long value to a properly encoded
    // byte[]
    final private static class ByteBuffer 
    {
        private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        
        public ByteBuffer append( long value ) 
        {
            write( value, false );
            return this;
        }
        
        private void write( long value, boolean hasMore )
        {
            long remaining = value >> 7;
            if ( remaining > 0 )
            {
                write( remaining, true );
            }
            buffer.write( hasMore 
                    ? (byte)((0x7F & value) | 0x80)
                    : (byte)(0x7F & value) );
        }
        
        public byte[] toByteArray() {
            return buffer.toByteArray();
        }
    }
}
