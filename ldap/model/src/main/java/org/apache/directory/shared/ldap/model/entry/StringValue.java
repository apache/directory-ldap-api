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

import org.apache.directory.shared.i18n.I18n;
import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.shared.ldap.model.schema.AttributeType;
import org.apache.directory.shared.ldap.model.schema.LdapComparator;
import org.apache.directory.shared.ldap.model.schema.Normalizer;
import org.apache.directory.shared.util.Strings;
import org.apache.directory.shared.util.exception.NotImplementedException;


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


    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------
    /**
     * Creates a StringValue without an initial wrapped value.
     *
     * @param attributeType the schema attribute type associated with this StringValue
     */
    /* No protection*/StringValue( AttributeType attributeType )
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

        if ( this.isNull() )
        {
            return other.isNull();
        }

        // First check the upValue. If they are equal, the Values are equal
        if ( wrappedValue == other.wrappedValue )
        {
            return true;
        }
        else if ( wrappedValue != null )
        {
            if ( wrappedValue.equals( other.wrappedValue ) )
            {
                return true;
            }
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
                return this.getNormValue().equals( other.getNormValue() );
            }
        }
        else if ( other.attributeType != null )
        {
            return this.getNormValue().equals( other.getNormValue() );
        }

        // Shortcut : compare the values without normalization
        // If they are equal, we may avoid a normalization.
        // Note : if two values are equal, then their normalized
        // value are equal too if their attributeType are equal. 
        if ( getReference().equals( other.getReference() ) )
        {
            return true;
        }

        if ( attributeType != null )
        {
            try
            {
                LdapComparator<String> comparator = getLdapComparator();

                // Compare normalized values
                if ( comparator == null )
                {
                    return getNormValue().equals( other.getNormValue() );
                }
                else
                {
                    if ( isSchemaAware() )
                    {
                        return comparator.compare( getNormValue(), other.getNormValue() ) == 0;
                    }
                    else
                    {
                        Normalizer normalizer = attributeType.getEquality().getNormalizer();
                        return comparator.compare( normalizer.normalize( getValue() ),
                            normalizer.normalize( other.getValue() ) ) == 0;
                    }
                }
            }
            catch ( LdapException ne )
            {
                return false;
            }
        }
        else
        {
            return this.getNormValue().equals( other.getNormValue() );
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
        return Strings.getBytesUtf8( wrappedValue );
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
            normalizedValue = wrappedValue;
        }

        // The hashCoe
        h = in.readInt();
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
