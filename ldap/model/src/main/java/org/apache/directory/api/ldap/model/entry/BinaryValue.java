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
package org.apache.directory.api.ldap.model.entry;


import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;
import java.util.Comparator;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.comparators.ByteArrayComparator;
import org.apache.directory.api.util.Strings;


/**
 * A server side schema aware wrapper around a binary attribute value.
 * This value wrapper uses schema information to syntax check values,
 * and to compare them for equality and ordering.  It caches results
 * and invalidates them when the user provided value changes.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class BinaryValue extends AbstractValue<byte[]>
{
    /** Used for serialization */
    public static final long serialVersionUID = 2L;


    /**
     * Creates a BinaryValue without an initial user provided value.
     *
     * @param attributeType the schema type associated with this BinaryValue
     */
    /* No protection */BinaryValue( AttributeType attributeType )
    {
        if ( attributeType != null )
        {
            // We must have a Syntax
            if ( attributeType.getSyntax() == null )
            {
                throw new IllegalArgumentException( I18n.err( I18n.ERR_04445 ) );
            }

            if ( attributeType.getSyntax().isHumanReadable() )
            {
                LOG.warn( "Treating a value of a human readible attribute {} as binary: ", attributeType.getName() );
            }

            this.attributeType = attributeType;
        }
    }


    /**
     * Creates a BinaryValue with an initial user provided binary value.
     *
     * @param value the binary value to wrap which may be null, or a zero length byte array
     */
    public BinaryValue( byte[] value )
    {
        if ( value != null )
        {
            this.upValue = new byte[value.length];
            this.normalizedValue = new byte[value.length];
            System.arraycopy( value, 0, this.upValue, 0, value.length );
            System.arraycopy( value, 0, this.normalizedValue, 0, value.length );
        }
        else
        {
            this.upValue = null;
            this.normalizedValue = null;
        }
    }


    /**
     * Creates a BinaryValue with an initial user provided binary value.
     *
     * @param attributeType the schema type associated with this BinaryValue
     * @param value the binary value to wrap which may be null, or a zero length byte array
     * @throws LdapInvalidAttributeValueException If the added value is invalid accordingly 
     * to the schema
     */
    public BinaryValue( AttributeType attributeType, byte[] value ) throws LdapInvalidAttributeValueException
    {
        this( value );
        apply( attributeType );
    }


    /**
     * Gets a direct reference to the normalized representation for the
     * user provided value of this ServerValue wrapper. Implementations will most
     * likely leverage the attributeType this value is associated with to
     * determine how to properly normalize the user provided value.
     *
     * @return the normalized version of the user provided value
     */
    @Override
    public byte[] getNormValue()
    {
        if ( isNull() )
        {
            return null;
        }

        byte[] copy = new byte[normalizedValue.length];
        System.arraycopy( normalizedValue, 0, copy, 0, normalizedValue.length );
        return copy;
    }


    /**
     * Compare the current value with a provided one
     *
     * @param value The value we want to compare to
     * @return -1 if the current is below the provided one, 1 if it's above, 0 if they are equal
     */
    @Override
    public int compareTo( Value<byte[]> value )
    {
        if ( isNull() )
        {
            if ( ( value == null ) || value.isNull() )
            {
                return 0;
            }
            else
            {
                return -1;
            }
        }
        else
        {
            if ( ( value == null ) || value.isNull() )
            {
                return 1;
            }
        }

        BinaryValue binaryValue = ( BinaryValue ) value;

        if ( attributeType != null )
        {
            try
            {
                LdapComparator<byte[]> comparator = getLdapComparator();

                if ( comparator != null )
                {
                    return comparator
                        .compare( getNormReference(), binaryValue.getNormReference() );
                }
                else
                {
                    return new ByteArrayComparator( null ).compare( getNormReference(), binaryValue
                        .getNormReference() );
                }
            }
            catch ( LdapException e )
            {
                String msg = I18n.err( I18n.ERR_04443, Arrays.toString( getReference() ), value );
                LOG.error( msg, e );
                throw new IllegalStateException( msg, e );
            }
        }
        else
        {
            return new ByteArrayComparator( null ).compare( getNormValue(), binaryValue.getNormValue() );
        }
    }


    // -----------------------------------------------------------------------
    // Object Methods
    // -----------------------------------------------------------------------
    /**
     * @see Object#hashCode()
     * @return the instance's hashcode 
     */
    @Override
    public int hashCode()
    {
        if ( h == 0 )
        {
            // return zero if the value is null so only one null value can be
            // stored in an attribute - the string version does the same
            if ( isNull() )
            {
                return 0;
            }

            byte[] normalizedValue = getNormReference();
            h = Arrays.hashCode( normalizedValue );
        }

        return h;
    }


    /**
     * Checks to see if this BinaryValue equals the supplied object.
     *
     * This equals implementation overrides the BinaryValue implementation which
     * is not schema aware.
     */
    @Override
    public boolean equals( Object obj )
    {
        if ( this == obj )
        {
            return true;
        }

        if ( !( obj instanceof BinaryValue ) )
        {
            return false;
        }

        BinaryValue other = ( BinaryValue ) obj;

        // First check if we have an attrbuteType.
        if ( attributeType != null )
        {
            // yes : check for the other value
            if ( other.attributeType != null )
            {
                if ( attributeType.getOid().equals( other.getAttributeType().getOid() ) )
                {
                    // Both AttributeType have the same OID, we can assume they are 
                    // equals. We don't check any further, because the unicity of OID
                    // makes it unlikely that the two AT are different.
                    // The values may be both null
                    if ( isNull() )
                    {
                        return other.isNull();
                    }

                    // Shortcut : if we have an AT for both the values, check the 
                    // already normalized values
                    if ( Arrays.equals( upValue, other.upValue ) )
                    {
                        return true;
                    }

                    // We have an AttributeType, we use the associated comparator
                    try
                    {
                        Comparator<byte[]> comparator = getLdapComparator();

                        // Compare normalized values
                        if ( comparator == null )
                        {
                            return Arrays.equals( getNormReference(), other.getNormReference() );
                        }
                        else
                        {
                            return comparator.compare( getNormReference(), other.getNormReference() ) == 0;
                        }
                    }
                    catch ( LdapException ne )
                    {
                        return false;
                    }
                }
                else
                {
                    // We can't compare two values when the two ATs are different
                    return false;
                }
            }
            else
            {
                // We only have one AT : we will assume that both values are for the 
                // same AT.
                // The values may be both null
                if ( isNull() )
                {
                    return other.isNull();
                }

                // We have an AttributeType on the base value, we need to use its comparator
                try
                {
                    Comparator<byte[]> comparator = getLdapComparator();

                    // Compare normalized values. We have to normalized the other value,
                    // as it has no AT
                    MatchingRule equality = getAttributeType().getEquality();

                    if ( equality == null )
                    {
                        // No matching rule : compare the raw values
                        return Arrays.equals( getNormReference(), other.getNormReference() );
                    }

                    Normalizer normalizer = equality.getNormalizer();

                    BinaryValue otherValue = ( BinaryValue ) normalizer.normalize( other );

                    if ( comparator == null )
                    {
                        return Arrays.equals( getNormReference(), otherValue.getNormReference() );
                    }
                    else
                    {
                        return comparator.compare( getNormReference(), otherValue.getNormReference() ) == 0;
                    }
                }
                catch ( LdapException ne )
                {
                    return false;
                }
            }
        }
        else
        {
            // No : check for the other value
            if ( other.attributeType != null )
            {
                // We only have one AT : we will assume that both values are for the 
                // same AT.
                // The values may be both null
                if ( isNull() )
                {
                    return other.isNull();
                }

                try
                {
                    Comparator<byte[]> comparator = other.getLdapComparator();

                    // Compare normalized values. We have to normalized the other value,
                    // as it has no AT
                    MatchingRule equality = other.getAttributeType().getEquality();

                    if ( equality == null )
                    {
                        // No matching rule : compare the raw values
                        return Arrays.equals( getNormReference(), other.getNormReference() );
                    }

                    Normalizer normalizer = equality.getNormalizer();

                    BinaryValue thisValue = ( BinaryValue ) normalizer.normalize( this );

                    if ( comparator == null )
                    {
                        return Arrays.equals( thisValue.getNormReference(), other.getNormReference() );
                    }
                    else
                    {
                        return comparator.compare( thisValue.getNormReference(), other.getNormReference() ) == 0;
                    }
                }
                catch ( LdapException ne )
                {
                    return false;
                }
            }
            else
            {
                // The values may be both null
                if ( isNull() )
                {
                    return other.isNull();
                }

                // Now check the normalized values
                return Arrays.equals( getNormReference(), other.getNormReference() );
            }
        }
    }


    // -----------------------------------------------------------------------
    // Cloneable methods
    // -----------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public BinaryValue clone()
    {
        BinaryValue clone = ( BinaryValue ) super.clone();

        // We have to copy the byte[], they are just referenced by suoer.clone()
        if ( normalizedValue != null )
        {
            clone.normalizedValue = new byte[normalizedValue.length];
            System.arraycopy( normalizedValue, 0, clone.normalizedValue, 0, normalizedValue.length );
        }

        if ( upValue != null )
        {
            clone.upValue = new byte[upValue.length];
            System.arraycopy( upValue, 0, clone.upValue, 0, upValue.length );
        }

        return clone;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getValue()
    {
        if ( upValue == null )
        {
            return null;
        }

        final byte[] copy = new byte[upValue.length];
        System.arraycopy( upValue, 0, copy, 0, upValue.length );

        return copy;
    }


    /**
     * Tells if the current value is Human Readable
     * 
     * @return <code>true</code> if the value is HR, <code>false</code> otherwise
     */
    @Override
    public boolean isHumanReadable()
    {
        return false;
    }


    /**
     * @return The length of the interned value
     */
    @Override
    public int length()
    {
        return upValue != null ? upValue.length : 0;
    }


    /**
     * Get the user provided value as a byte[]. This method returns a copy of 
     * the user provided byte[].
     * 
     * @return the user provided value as a byte[]
     */
    @Override
    public byte[] getBytes()
    {
        return getValue();
    }


    /**
     * Get the user provided value as a String.
     *
     * @return the user provided value as a String
     */
    @Override
    public String getString()
    {
        return Strings.utf8ToString( upValue );
    }


    /**
     * Deserialize a BinaryValue. It will return a new BinaryValue instance.
     * 
     * @param in The input stream
     * @return A new StringValue instance
     * @throws IOException If the stream can't be read
     * @throws ClassNotFoundException If we can't instanciate a BinaryValue
     */
    public static BinaryValue deserialize( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        BinaryValue value = new BinaryValue( ( AttributeType ) null );
        value.readExternal( in );

        return value;
    }


    /**
     * Deserialize a schema aware BinaryValue. It will return a new BinaryValue instance.
     * 
     * @param attributeType The AttributeType associated with the Value. Can be null
     * @param in The input stream
     * @return A new StringValue instance
     * @throws IOException If the stream can't be read
     * @throws ClassNotFoundException If we can't instanciate a BinaryValue
     */
    public static BinaryValue deserialize( AttributeType attributeType, ObjectInput in ) throws IOException,
        ClassNotFoundException
    {
        BinaryValue value = new BinaryValue( attributeType );
        value.readExternal( in );

        return value;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void readExternal( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        // Read the BINARY flag
        boolean isHR = in.readBoolean();

        if ( isHR )
        {
            throw new IOException( "The serialized value is not a Binary value" );
        }
        // Read the user provided value, if it's not null
        int upLength = in.readInt();

        if ( upLength >= 0 )
        {
            upValue = new byte[upLength];

            in.readFully( upValue );
        }

        // Read the isNormalized flag
        boolean normalized = in.readBoolean();

        if ( normalized )
        {
            int normalizedLength = in.readInt();

            if ( normalizedLength >= 0 )
            {
                normalizedValue = new byte[normalizedLength];

                in.readFully( normalizedValue );
            }
        }
        else
        {
            if ( attributeType != null )
            {
                try
                {
                    normalizedValue = attributeType.getEquality().getNormalizer().normalize( this ).getBytes();
                    MatchingRule equality = attributeType.getEquality();

                    if ( equality == null )
                    {
                        if ( upLength >= 0 )
                        {
                            normalizedValue = new byte[upLength];

                            System.arraycopy( upValue, 0, normalizedValue, 0, upLength );
                        }
                    }
                    else
                    {
                        Normalizer normalizer = equality.getNormalizer();

                        if ( normalizer != null )
                        {
                            normalizedValue = normalizer.normalize( this ).getBytes();
                        }
                        else
                        {
                            if ( upLength >= 0 )
                            {
                                normalizedValue = new byte[upLength];

                                System.arraycopy( upValue, 0, normalizedValue, 0, upLength );
                            }
                        }
                    }
                }
                catch ( LdapException le )
                {
                    // Copy the upValue into the normalizedValue
                    if ( upLength >= 0 )
                    {
                        normalizedValue = new byte[upLength];

                        System.arraycopy( upValue, 0, normalizedValue, 0, upLength );
                    }
                }
            }
            else
            {
                // Copy the upValue into the normalizedValue
                if ( upLength >= 0 )
                {
                    normalizedValue = new byte[upLength];

                    System.arraycopy( upValue, 0, normalizedValue, 0, upLength );
                }
            }
        }

        // The hashCoe
        h = in.readInt();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void writeExternal( ObjectOutput out ) throws IOException
    {
        // Write the BINARY flag
        out.writeBoolean( BINARY );

        // Write the user provided value, if it's not null
        if ( upValue != null )
        {
            out.writeInt( upValue.length );

            if ( upValue.length > 0 )
            {
                out.write( upValue, 0, upValue.length );
            }
        }
        else
        {
            out.writeInt( -1 );
        }

        // Write the isNormalized flag
        if ( attributeType != null )
        {
            out.writeBoolean( true );

            // Write the normalized value, if not null
            if ( normalizedValue != null )
            {
                out.writeInt( normalizedValue.length );

                if ( normalizedValue.length > 0 )
                {
                    out.write( normalizedValue, 0, normalizedValue.length );
                }
            }
            else
            {
                out.writeInt( -1 );
            }
        }
        else
        {
            out.writeBoolean( false );
        }

        // The hashCode
        out.writeInt( h );

        out.flush();
    }


    /**
     * Dumps binary in hex with label.
     *
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        if ( upValue == null )
        {
            return "null";
        }
        else if ( upValue.length > 16 )
        {
            // Just dump the first 16 bytes...
            byte[] copy = new byte[16];

            System.arraycopy( upValue, 0, copy, 0, 16 );

            return Strings.dumpBytes( copy ) + "...";
        }
        else
        {
            return Strings.dumpBytes( upValue );
        }
    }
}