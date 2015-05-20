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
import java.util.Comparator;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.util.Serialize;
import org.apache.directory.api.util.Strings;
import org.apache.directory.api.util.exception.NotImplementedException;


/**
 * A server side schema aware wrapper around a String attribute value.
 * This value wrapper uses schema information to syntax check values,
 * and to compare them for equality and ordering.  It caches results
 * and invalidates them when the wrapped value changes.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StringValue extends AbstractValue<String>
{
    /** Used for serialization */
    private static final long serialVersionUID = 2L;

    /** The UTF-8 bytes for this value */
    private byte[] bytes;


    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------
    /**
     * Creates a StringValue without an initial wrapped value.
     *
     * @param attributeType the schema attribute type associated with this StringValue
     */
    public StringValue( AttributeType attributeType )
    {
        if ( attributeType != null )
        {
            // We must have a Syntax
            if ( attributeType.getSyntax() == null )
            {
                throw new IllegalArgumentException( I18n.err( I18n.ERR_04445 ) );
            }

            if ( !attributeType.getSyntax().isHumanReadable() )
            {
                LOG.warn( "Treating a value of a binary attribute {} as a String: "
                    + "\nthis could cause data corruption!", attributeType.getName() );
            }

            this.attributeType = attributeType;
        }
    }


    /**
     * Creates a StringValue with an initial wrapped String value.
     *
     * @param value the value to wrap which can be null
     */
    public StringValue( String value )
    {
        this.wrappedValue = value;
        this.normalizedValue = value;
        bytes = Strings.getBytesUtf8( value );
    }


    /**
     * Creates a schema aware StringValue with an initial wrapped String value.
     *
     * @param attributeType the schema type associated with this StringValue
     * @param value the value to wrap
     * @throws LdapInvalidAttributeValueException If the added value is invalid accordingly
     * to the schema
     */
    public StringValue( AttributeType attributeType, String value ) throws LdapInvalidAttributeValueException
    {
        this( value );
        apply( attributeType );
    }


    // -----------------------------------------------------------------------
    // Value<String> Methods
    // -----------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    public String getValue()
    {
        // The String is immutable, we can safely return the internal
        // object without copying it.
        return wrappedValue;
    }


    /**
     * {@inheritDoc}
     */
    public String getNormValue()
    {
        return normalizedValue;
    }


    // -----------------------------------------------------------------------
    // Comparable<String> Methods
    // -----------------------------------------------------------------------
    /**
     * @see ServerValue#compareTo(Value)
     * @throws IllegalStateException on failures to extract the comparator, or the
     * normalizers needed to perform the required comparisons based on the schema
     */
    public int compareTo( Value<String> value )
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
        else if ( ( value == null ) || value.isNull() )
        {
            return 1;
        }

        if ( !( value instanceof StringValue ) )
        {
            String message = I18n.err( I18n.ERR_04128, toString(), value.getClass() );
            LOG.error( message );
            throw new NotImplementedException( message );
        }

        StringValue stringValue = ( StringValue ) value;

        if ( attributeType != null )
        {
            if ( stringValue.getAttributeType() == null )
            {
                return getNormValue().compareTo( stringValue.getNormValue() );
            }
            else
            {
                if ( !attributeType.equals( stringValue.getAttributeType() ) )
                {
                    String message = I18n.err( I18n.ERR_04128, toString(), value.getClass() );
                    LOG.error( message );
                    throw new NotImplementedException( message );
                }
            }
        }
        else
        {
            return getNormValue().compareTo( stringValue.getNormValue() );
        }

        try
        {
            return getLdapComparator().compare( getNormValue(), stringValue.getNormValue() );
        }
        catch ( LdapException e )
        {
            String msg = I18n.err( I18n.ERR_04443, this, value );
            LOG.error( msg, e );
            throw new IllegalStateException( msg, e );
        }
    }


    // -----------------------------------------------------------------------
    // Cloneable methods
    // -----------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    public StringValue clone()
    {
        return ( StringValue ) super.clone();
    }


    // -----------------------------------------------------------------------
    // Object Methods
    // -----------------------------------------------------------------------
    /**
     * @see Object#hashCode()
     * @return the instance's hashcode
     */
    public int hashCode()
    {
        if ( h == 0 )
        {
            // return zero if the value is null so only one null value can be
            // stored in an attribute - the binary version does the same
            if ( isNull() )
            {
                return 0;
            }

            // If the normalized value is null, will default to wrapped
            // which cannot be null at this point.
            // If the normalized value is null, will default to wrapped
            // which cannot be null at this point.
            String normalized = getNormValue();

            if ( normalized != null )
            {
                h = normalized.hashCode();
            }
            else
            {
                h = 17;
            }
        }

        return h;
    }


    /**
     * Two StringValue are equals if their normalized values are equal
     * 
     * @see Object#equals(Object)
     */
    public boolean equals( Object obj )
    {
        if ( this == obj )
        {
            return true;
        }

        if ( !( obj instanceof StringValue ) )
        {
            return false;
        }

        StringValue other = ( StringValue ) obj;

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
                    if ( wrappedValue.equals( other.wrappedValue ) )
                    {
                        return true;
                    }

                    // We have an AttributeType, we use the associated comparator
                    try
                    {
                        Comparator<String> comparator = getLdapComparator();

                        // Compare normalized values
                        if ( comparator == null )
                        {
                            return getNormReference().equals( other.getNormReference() );
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
                    Comparator<String> comparator = getLdapComparator();

                    // Compare normalized values. We have to normalized the other value,
                    // as it has no AT
                    MatchingRule equality = getAttributeType().getEquality();

                    if ( equality == null )
                    {
                        // No matching rule : compare the raw values
                        return getNormReference().equals( other.getNormReference() );
                    }

                    Normalizer normalizer = equality.getNormalizer();

                    StringValue otherValue = ( StringValue ) normalizer.normalize( other );

                    if ( comparator == null )
                    {
                        return getNormReference().equals( otherValue.getNormReference() );
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
                    Comparator<String> comparator = other.getLdapComparator();

                    // Compare normalized values. We have to normalized the other value,
                    // as it has no AT
                    MatchingRule equality = other.getAttributeType().getEquality();

                    if ( equality == null )
                    {
                        // No matching rule : compare the raw values
                        return getNormReference().equals( other.getNormReference() );
                    }

                    Normalizer normalizer = equality.getNormalizer();

                    StringValue thisValue = ( StringValue ) normalizer.normalize( this );

                    if ( comparator == null )
                    {
                        return thisValue.getNormReference().equals( other.getNormReference() );
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
                return getNormReference().equals( other.getNormReference() );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    public boolean isHumanReadable()
    {
        return true;
    }


    /**
     * @return The length of the interned value
     */
    public int length()
    {
        return wrappedValue != null ? wrappedValue.length() : 0;
    }


    /**
     * Get the wrapped value as a byte[].
     * @return the wrapped value as a byte[]
     */
    public byte[] getBytes()
    {
        return bytes;
    }


    /**
     * Get the wrapped value as a String.
     *
     * @return the wrapped value as a String
     */
    public String getString()
    {
        return wrappedValue != null ? wrappedValue : "";
    }


    /**
     * Deserialize a StringValue. It will return a new StringValue instance.
     * 
     * @param in The input stream
     * @return A new StringValue instance
     * @throws IOException If the stream can't be read
     * @throws ClassNotFoundException If we can't instanciate a StringValue
     */
    public static StringValue deserialize( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        StringValue value = new StringValue( ( AttributeType ) null );
        value.readExternal( in );

        return value;
    }


    /**
     * Deserialize a schemaAware StringValue. It will return a new StringValue instance.
     * 
     * @param attributeType The AttributeType associated with the Value. Can be null
     * @param in The input stream
     * @return A new StringValue instance
     * @throws IOException If the stream can't be read
     * @throws ClassNotFoundException If we can't instanciate a StringValue
     */
    public static StringValue deserialize( AttributeType attributeType, ObjectInput in ) throws IOException,
        ClassNotFoundException
    {
        StringValue value = new StringValue( attributeType );
        value.readExternal( in );

        return value;
    }


    /**
     * {@inheritDoc}
     */
    public void readExternal( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        // Read the STRING flag
        boolean isHR = in.readBoolean();

        if ( !isHR )
        {
            throw new IOException( "The serialized value is not a String value" );
        }

        // Read the wrapped value, if it's not null
        if ( in.readBoolean() )
        {
            wrappedValue = in.readUTF();
            bytes = Strings.getBytesUtf8( wrappedValue );
        }

        // Read the isNormalized flag
        boolean normalized = in.readBoolean();

        if ( normalized )
        {
            // Read the normalized value, if not null
            if ( in.readBoolean() )
            {
                normalizedValue = in.readUTF();
            }
        }
        else
        {
            if ( attributeType != null )
            {
                try
                {
                    MatchingRule equality = attributeType.getEquality();

                    if ( equality == null )
                    {
                        normalizedValue = wrappedValue;
                    }
                    else
                    {
                        Normalizer normalizer = equality.getNormalizer();

                        if ( normalizer != null )
                        {
                            normalizedValue = normalizer.normalize( wrappedValue );
                        }
                        else
                        {
                            normalizedValue = wrappedValue;
                        }
                    }
                }
                catch ( LdapException le )
                {
                    normalizedValue = wrappedValue;
                }
            }
            else
            {
                normalizedValue = wrappedValue;
            }
        }

        // The hashCoe
        h = in.readInt();
    }


    /**
     * Serialize the StringValue into a buffer at the given position.
     * 
     * @param buffer The buffer which will contain the serialized StringValue
     * @param pos The position in the buffer for the serialized value
     * @return The new position in the buffer
     */
    public int serialize( byte[] buffer, int pos )
    {
        // Compute the length
        // The value type, the wrappedValue presence flag,
        // the normalizedValue presence flag and the hash length.
        int length = 1 + 1 + 1 + 4;

        byte[] wrappedValueBytes = null;
        byte[] normalizedValueBytes = null;

        if ( wrappedValue != null )
        {
            wrappedValueBytes = Strings.getBytesUtf8( wrappedValue );
            length += 4 + wrappedValueBytes.length;
        }

        if ( attributeType != null )
        {
            if ( normalizedValue != null )
            {
                normalizedValueBytes = Strings.getBytesUtf8( normalizedValue );
                length += 1 + 4 + normalizedValueBytes.length;
            }
            else
            {
                length += 1;
            }
        }

        // Check that we will be able to store the data in the buffer
        if ( buffer.length - pos < length )
        {
            throw new ArrayIndexOutOfBoundsException();
        }

        // The STRING flag
        buffer[pos] = Serialize.TRUE;
        pos++;

        // Write the wrapped value, if it's not null
        if ( wrappedValue != null )
        {
            buffer[pos++] = Serialize.TRUE;
            pos = Serialize.serialize( wrappedValueBytes, buffer, pos );
        }
        else
        {
            buffer[pos++] = Serialize.FALSE;
        }

        // Write the isNormalized flag
        if ( attributeType != null )
        {
            // This flag is present to tell that we have a normalized value different
            // from the upValue

            buffer[pos++] = Serialize.TRUE;

            // Write the normalized value, if not null
            if ( normalizedValue != null )
            {
                buffer[pos++] = Serialize.TRUE;
                pos = Serialize.serialize( normalizedValueBytes, buffer, pos );
            }
            else
            {
                buffer[pos++] = Serialize.FALSE;
            }
        }
        else
        {
            // No normalized value
            buffer[pos++] = Serialize.FALSE;
        }

        // Write the hashCode
        pos = Serialize.serialize( h, buffer, pos );

        return pos;
    }


    /**
     * Deserialize a StringValue from a byte[], starting at a given position
     * 
     * @param buffer The buffer containing the StringValue
     * @param pos The position in the buffer
     * @return The new position
     * @throws IOException If the serialized value is not a StringValue
     */
    public int deserialize( byte[] buffer, int pos ) throws IOException
    {
        if ( ( pos < 0 ) || ( pos >= buffer.length ) )
        {
            throw new ArrayIndexOutOfBoundsException();
        }

        // Read the STRING flag
        boolean isHR = Serialize.deserializeBoolean( buffer, pos );
        pos++;

        if ( !isHR )
        {
            throw new IOException( "The serialized value is not a String value" );
        }

        // Read the wrapped value, if it's not null
        boolean hasWrappedValue = Serialize.deserializeBoolean( buffer, pos );
        pos++;

        if ( hasWrappedValue )
        {
            byte[] wrappedValueBytes = Serialize.deserializeBytes( buffer, pos );
            pos += 4 + wrappedValueBytes.length;
            wrappedValue = Strings.utf8ToString( wrappedValueBytes );
        }

        // Read the isNormalized flag
        boolean hasAttributeType = Serialize.deserializeBoolean( buffer, pos );
        pos++;

        if ( hasAttributeType )
        {
            // Read the normalized value, if not null
            boolean hasNormalizedValue = Serialize.deserializeBoolean( buffer, pos );
            pos++;

            if ( hasNormalizedValue )
            {
                byte[] normalizedValueBytes = Serialize.deserializeBytes( buffer, pos );
                pos += 4 + normalizedValueBytes.length;
                normalizedValue = Strings.utf8ToString( normalizedValueBytes );
            }
        }
        else
        {
            if ( attributeType != null )
            {
                try
                {
                    MatchingRule equality = attributeType.getEquality();

                    if ( equality == null )
                    {
                        normalizedValue = wrappedValue;
                    }
                    else
                    {
                        Normalizer normalizer = equality.getNormalizer();

                        if ( normalizer != null )
                        {
                            normalizedValue = normalizer.normalize( wrappedValue );
                        }
                        else
                        {
                            normalizedValue = wrappedValue;
                        }
                    }
                }
                catch ( LdapException le )
                {
                    normalizedValue = wrappedValue;
                }
            }
            else
            {
                normalizedValue = wrappedValue;
            }
        }

        // The hashCode
        h = Serialize.deserializeInt( buffer, pos );
        pos += 4;

        return pos;
    }


    /**
     * {@inheritDoc}
     */
    public void writeExternal( ObjectOutput out ) throws IOException
    {
        // Write a boolean for the HR flag
        out.writeBoolean( STRING );

        // Write the wrapped value, if it's not null
        if ( wrappedValue != null )
        {
            out.writeBoolean( true );
            out.writeUTF( wrappedValue );
        }
        else
        {
            out.writeBoolean( false );
        }

        // Write the isNormalized flag
        if ( attributeType != null )
        {
            // This flag is present to tell that we have a normalized value different
            // from the upValue
            out.writeBoolean( true );

            // Write the normalized value, if not null
            if ( normalizedValue != null )
            {
                out.writeBoolean( true );
                out.writeUTF( normalizedValue );
            }
            else
            {
                out.writeBoolean( false );
            }
        }
        else
        {
            // No normalized value
            out.writeBoolean( false );
        }

        // Write the hashCode
        out.writeInt( h );

        // and flush the data
        out.flush();
    }


    /**
     * @see Object#toString()
     */
    public String toString()
    {
        return wrappedValue == null ? "null" : wrappedValue;
    }
}
