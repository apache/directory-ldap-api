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
package org.apache.directory.shared.ldap.model.entry;


import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;
import java.util.Comparator;

import org.apache.directory.shared.i18n.I18n;
import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.shared.ldap.model.schema.AttributeType;
import org.apache.directory.shared.ldap.model.schema.LdapComparator;
import org.apache.directory.shared.ldap.model.schema.comparators.ByteArrayComparator;
import org.apache.directory.shared.util.Strings;


/**
 * A server side schema aware wrapper around a binary attribute value.
 * This value wrapper uses schema information to syntax check values,
 * and to compare them for equality and ordering.  It caches results
 * and invalidates them when the wrapped value changes.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class BinaryValue extends AbstractValue<byte[]>
{
    /** Used for serialization */
    public static final long serialVersionUID = 2L;


    /**
     * Creates a BinaryValue without an initial wrapped value.
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
     * Creates a BinaryValue with an initial wrapped binary value.
     *
     * @param value the binary value to wrap which may be null, or a zero length byte array
     */
    public BinaryValue( byte[] value )
    {
        if ( value != null )
        {
            this.wrappedValue = new byte[value.length];
            this.normalizedValue = new byte[value.length];
            System.arraycopy( value, 0, this.wrappedValue, 0, value.length );
            System.arraycopy( value, 0, this.normalizedValue, 0, value.length );
        }
        else
        {
            this.wrappedValue = null;
            this.normalizedValue = null;
        }
    }


    /**
     * Creates a BinaryValue with an initial wrapped binary value.
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
     * wrapped value of this ServerValue wrapper. Implementations will most
     * likely leverage the attributeType this value is associated with to
     * determine how to properly normalize the wrapped value.
     *
     * @return the normalized version of the wrapped value
     */
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
     *
     * @see ServerValue#compareTo(Value)
     */
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

        if ( isNull() )
        {
            return other.isNull();
        }

        // If we have an attributeType, it must be equal
        // We should also use the comparator if we have an AT
        if ( attributeType != null )
        {
            if ( other.attributeType != null )
            {
                if ( !attributeType.equals( other.attributeType ) )
                {
                    return false;
                }
            }
            else
            {
                other.attributeType = attributeType;
            }
        }
        else if ( other.attributeType != null )
        {
            attributeType = other.attributeType;
        }

        // Shortcut : if the values are equals, no need to compare
        // the normalized values
        if ( Arrays.equals( wrappedValue, other.wrappedValue ) )
        {
            return true;
        }

        if ( attributeType != null )
        {
            // We have an AttributeType, we eed to use the comparator
            try
            {
                Comparator<byte[]> comparator = ( Comparator<byte[]> ) getLdapComparator();

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
            // now unlike regular values we have to compare the normalized values
            return Arrays.equals( getNormReference(), other.getNormReference() );
        }
    }


    // -----------------------------------------------------------------------
    // Cloneable methods
    // -----------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    public BinaryValue clone()
    {
        BinaryValue clone = ( BinaryValue ) super.clone();

        // We have to copy the byte[], they are just referenced by suoer.clone()
        if ( normalizedValue != null )
        {
            clone.normalizedValue = new byte[normalizedValue.length];
            System.arraycopy( normalizedValue, 0, clone.normalizedValue, 0, normalizedValue.length );
        }

        if ( wrappedValue != null )
        {
            clone.wrappedValue = new byte[wrappedValue.length];
            System.arraycopy( wrappedValue, 0, clone.wrappedValue, 0, wrappedValue.length );
        }

        return clone;
    }


    /**
     * {@inheritDoc}
     */
    public byte[] getValue()
    {
        if ( wrappedValue == null )
        {
            return null;
        }

        final byte[] copy = new byte[wrappedValue.length];
        System.arraycopy( wrappedValue, 0, copy, 0, wrappedValue.length );

        return copy;
    }


    /**
     * Tells if the current value is Human Readable
     * 
     * @return <code>true</code> if the value is HR, <code>false</code> otherwise
     */
    public boolean isHumanReadable()
    {
        return false;
    }


    /**
     * @return The length of the interned value
     */
    public int length()
    {
        return wrappedValue != null ? wrappedValue.length : 0;
    }


    /**
     * Get the wrapped value as a byte[]. This method returns a copy of 
     * the wrapped byte[].
     * 
     * @return the wrapped value as a byte[]
     */
    public byte[] getBytes()
    {
        return getValue();
    }


    /**
     * Get the wrapped value as a String.
     *
     * @return the wrapped value as a String
     */
    public String getString()
    {
        return Strings.utf8ToString( wrappedValue );
    }


    /**
     * Deserialize a BinaryValue. It will return a new BinaryValue instance.
     * 
     * @param attributeType The AttributeType associated with the Value. Can be null
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
    public void readExternal( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        // Read the BINARY flag
        boolean isHR = in.readBoolean();

        if ( isHR )
        {
            throw new IOException( "The serialized value is not a Binary value" );
        }
        // Read the wrapped value, if it's not null
        int wrappedLength = in.readInt();

        if ( wrappedLength >= 0 )
        {
            wrappedValue = new byte[wrappedLength];

            in.readFully( wrappedValue );
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
            // Copy the wrappedValue into the normalizedValue
            if ( wrappedLength >= 0 )
            {
                normalizedValue = new byte[wrappedLength];

                System.arraycopy( wrappedValue, 0, normalizedValue, 0, wrappedLength );
            }
        }

        // The hashCoe
        h = in.readInt();
    }


    /**
     * {@inheritDoc}
     */
    public void writeExternal( ObjectOutput out ) throws IOException
    {
        // Write the BINARY flag
        out.writeBoolean( BINARY );

        // Write the wrapped value, if it's not null
        if ( wrappedValue != null )
        {
            out.writeInt( wrappedValue.length );

            if ( wrappedValue.length > 0 )
            {
                out.write( wrappedValue, 0, wrappedValue.length );
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
    public String toString()
    {
        if ( wrappedValue == null )
        {
            return "null";
        }
        else if ( wrappedValue.length > 16 )
        {
            // Just dump the first 16 bytes...
            byte[] copy = new byte[16];

            System.arraycopy( wrappedValue, 0, copy, 0, 16 );

            return "'" + Strings.dumpBytes( copy ) + "...'";
        }
        else
        {
            return "'" + Strings.dumpBytes( wrappedValue ) + "'";
        }
    }
}