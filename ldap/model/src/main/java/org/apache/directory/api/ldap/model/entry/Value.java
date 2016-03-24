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
package org.apache.directory.api.ldap.model.entry;


import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;
import java.util.Comparator;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.util.Serialize;
import org.apache.directory.api.util.Strings;
import org.apache.directory.api.util.exception.NotImplementedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A interface for wrapping attribute values stored into an EntryAttribute. These
 * values can be a String or a byte[].
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class Value implements Cloneable, Externalizable, Comparable<Value>
{
    /** Used for serialization */
    private static final long serialVersionUID = 2L;

    /** logger for reporting errors that might not be handled properly upstream */
    private static final Logger LOG = LoggerFactory.getLogger( Value.class );

    /** reference to the attributeType zssociated with the value */
    private transient AttributeType attributeType;

    /** the User Provided value if it's a String */
    private String upValue;

    /** the canonical representation of the user provided value if it's a String */
    private String normValue;

    /** The computed hashcode. We don't want to compute it each time the hashcode() method is called */
    private volatile int h;

    /** The UTF-8 bytes for this value (we use the UP value) */
    private byte[] upBytes;

    /** The UTF-8 bytes for this value (we use the NORM value) */
    private byte[] normBytes;

    /** Two flags used to tell if the value is HR or not in serialization */
    private boolean isHR = true;
    
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------
    /**
     * Creates a Value with an initial user provided String value.
     *
     * @param value the value to wrap which can be null
     */
    public Value( String value )
    {
        upValue = value;
        normValue = value;
        
        if ( value != null )
        {
            upBytes = Strings.getBytesUtf8( value );
        }
        
        normBytes = upBytes;
        isHR = true;
        h = hashCode();
    }
    
    
    /**
     * Creates a Value with an initial user provided binary value.
     *
     * @param value the binary value to wrap which may be null, or a zero length byte array
     */
    public Value( byte[] value )
    {
        isHR = false;
        
        if ( value != null )
        {
            upBytes = new byte[value.length];
            System.arraycopy( value, 0, upBytes, 0, value.length );
            
            normBytes = upBytes;
            h = hashCode();
        }
        else
        {
            upBytes = null;
            normBytes = null;
        }
    }


    
    /**
     * Creates a Value with an initial user provided String value and a normalized value.
     *
     * @param upValue the user provided value to wrap which can be null
     * @param normValue the normalized value to wrap which can be null
     */
    public Value( String upValue, String normalizedValue )
    {
        this.upValue = upValue;
        this.normValue = normalizedValue;
        
        if ( upValue != null )
        {
            upBytes = Strings.getBytesUtf8( upValue );
        }
        else
        {
            upBytes = null;
        }

        if ( normalizedValue != null )
        {
            normBytes = Strings.getBytesUtf8( normalizedValue );
        }
        else
        {
            normBytes = null;
        }

        isHR = true;
        h = hashCode();
    }


    /**
     * Creates a schema aware binary Value with an initial value.
     *
     * @param attributeType the schema type associated with this Value
     * @param value the value to wrap
     * @throws LdapInvalidAttributeValueException If the added value is invalid accordingly
     * to the schema
     */
    public Value( AttributeType attributeType, byte[] value ) throws LdapInvalidAttributeValueException
    {
        isHR = false;
        
        if ( value != null )
        {
            upBytes = new byte[value.length];
            System.arraycopy( value, 0, upBytes, 0, value.length );
        }
        else
        {
            upBytes = null;
        }

        apply( attributeType );
    }


    /**
     * Creates a schema aware binary Value with an initial value.
     *
     * @param attributeType the schema type associated with this Value
     * @param value the value to wrap
     */
    /* Package protected*/ Value( AttributeType attributeType )
    {
        // The AttributeType must have a Syntax
        // We must have a Syntax
        if ( attributeType != null )
        {
            if ( attributeType.getSyntax() == null )
            {
                throw new IllegalArgumentException( I18n.err( I18n.ERR_04445 ) );
            }
            else
            {
                isHR = attributeType.getSyntax().isHumanReadable();
            }
        }

        this.attributeType = attributeType;
    }
    
    
    /**
     * Creates a schema aware StringValue with an initial user provided String value.
     *
     * @param attributeType the schema type associated with this StringValue
     * @param value the value to wrap
     * @throws LdapInvalidAttributeValueException If the added value is invalid accordingly
     * to the schema
     */
    public Value( AttributeType attributeType, String value ) throws LdapInvalidAttributeValueException
    {
        upValue = value;
        normValue = value;
        
        if ( value != null )
        {
            upBytes = Strings.getBytesUtf8( value );
        }
        else
        {
            upBytes = null;
        }
        
        apply( attributeType );
    }


    /**
     * Creates a schema aware Value with an initial user provided String value.
     *
     * @param attributeType the schema type associated with this StringValue
     * @param upValue the value to wrap
     * @throws LdapInvalidAttributeValueException If the added value is invalid accordingly
     * to the schema
     */
    public Value( AttributeType attributeType, String upValue, String normValue ) throws LdapInvalidAttributeValueException
    {
        this.upValue = upValue;
        this.normValue = normValue;

        if ( upValue != null )
        {
            upBytes = Strings.getBytesUtf8( upValue );
        }
        else
        {
            upBytes = null;
        }
        
        apply( attributeType );
    }


    
    /**
     * Creates a StringValue without an initial user provided value.
     *
     * @param attributeType the schema attribute type associated with this StringValue
     * @param value the original Value
     */
    public Value( AttributeType attributeType, Value value ) throws LdapInvalidAttributeValueException
    {
        if ( attributeType != null )
        {
            // We must have a Syntax
            if ( attributeType.getSyntax() == null )
            {
                throw new IllegalArgumentException( I18n.err( I18n.ERR_04445 ) );
            }

            isHR = attributeType.getSyntax().isHumanReadable();
            
            if ( isHR )
            {
                upValue = value.upValue;
            }
            
            // We have to copy the byte[], they are just referenced by suoer.clone()
            if ( value.upBytes != null )
            {
                upBytes = new byte[value.upBytes.length];
                System.arraycopy( value.upBytes, 0, upBytes, 0, value.upBytes.length );
            }

            apply( attributeType );
        }
    }

    
    /**
     * Create a Value with an AttributeType. It will not contain anything and will only be used by
     * the deserializer.
     * 
     * @param attributeType The ATttributeType to use
     * @return An instance of value.
     */
    public static Value createValue( AttributeType attributeType )
    {
        Value value = new Value( attributeType );
        
        return value;
    }

    /**
     * Clone a Value
     * 
     * @return A cloned value
     */
    public Value clone()
    {
        try
        {
            Value clone = ( Value ) super.clone();
            
            if ( isHR )
            {
                return clone;
            }
            else
            {
                // We have to copy the byte[], they are just referenced by suoer.clone()
                if ( upBytes != null )
                {
                    clone.upBytes = new byte[upBytes.length];
                    System.arraycopy( upBytes, 0, clone.upBytes, 0, upBytes.length );
    
                    clone.normBytes = new byte[normBytes.length];
                    System.arraycopy( normBytes, 0, clone.normBytes, 0, normBytes.length );
                }
            }
            
            return clone;
        }
        catch ( CloneNotSupportedException cnse )
        {
            // Do nothing
            return null;
        }
    }


    /**
     * Check if the contained value is null or not
     * 
     * @return <code>true</code> if the inner value is null.
     */
    public boolean isNull()
    {
        if ( isHR )
        {
            return normValue == null;
        }
        else
        {
            return normBytes == null;
        }
    }


    /**
     * Get the associated AttributeType
     * 
     * @return The AttributeType
     */
    public AttributeType getAttributeType()
    {
        return attributeType;
    }


    /**
     * Check if the value is stored into an instance of the given
     * AttributeType, or one of its ascendant.
     * 
     * For instance, if the Value is associated with a CommonName,
     * checking for Name will match.
     * 
     * @param attributeType The AttributeType we are looking at
     * @return <code>true</code> if the value is associated with the given
     * attributeType or one of its ascendant
     */
    public boolean isInstanceOf( AttributeType attributeType )
    {
        return ( attributeType != null )
            && ( this.attributeType.equals( attributeType ) || this.attributeType.isDescendantOf( attributeType ) );
    }


    /**
     * Get the User Provided value. It will return a copy, not a reference.
     *
     * @return a copy of the wrapped value
     */
    public String getValue()
    {
        if ( isHR )
        {
            return upValue;
        }
        else
        {
            return null;
        }
    }


    /**
     * Get the wrapped value as a byte[]. If the original value
     * is binary, this method will return a copy of the wrapped byte[]
     *
     * @return the wrapped value as a byte[]
     */
    public byte[] getBytes()
    {
        if ( Strings.isEmpty( upBytes ) )
        {
            return upBytes;
        }
        
        byte[] copy = new byte[upBytes.length];
        System.arraycopy( upBytes, 0, copy, 0, upBytes.length );
        
        return copy;
    }


    /**
     * Get the user provided value as a String. If the original value
     * is binary, this method will return the value as if it was
     * an UTF-8 encoded String.
     *
     * @return the wrapped value as a String
     */
    public String getString()
    {
        if ( isHR )
        {
            return upValue != null ? upValue : "";
        }
        else
        {
            return Strings.utf8ToString( upBytes );
        }
    }


    /**
     * Tells if the value is schema aware or not.
     *
     * @return <code>true</code> if the value is sxhema aware
     */
    public boolean isSchemaAware()
    {
        return attributeType != null;
    }


    /**
     * Uses the syntaxChecker associated with the attributeType to check if the
     * value is valid.
     * 
     * @param checker the SyntaxChecker to use to validate the value
     * @return <code>true</code> if the value is valid
     * @exception LdapInvalidAttributeValueException if the value cannot be validated
     */
    public final boolean isValid( SyntaxChecker syntaxChecker ) throws LdapInvalidAttributeValueException
    {
        if ( syntaxChecker == null )
        {
            String message = I18n.err( I18n.ERR_04139, toString() );
            LOG.error( message );
            throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, message );
        }

        if ( ( attributeType != null ) && attributeType.isRelaxed() ) 
        {
            return true;
        }
        else
        { 
            if ( isHR )
            {
                return syntaxChecker.isValidSyntax( normValue );
            }
            else
            {
                return syntaxChecker.isValidSyntax( normBytes );
            }
        }
    }


    /**
     * Gets the normalized (canonical) representation for the wrapped string.
     * If the wrapped String is null, null is returned, otherwise the normalized
     * form is returned.  If the normalizedValue is null, then this method
     * will attempt to generate it from the wrapped value.
     *
     * @return gets the normalized value
     */
    public String getNormValue()
    {
        if ( isHR )
        {
            return normValue;
        }
        else
        {
            if ( normBytes != null )
            {
                return Strings.utf8ToString( normBytes );
            }
            else
            {
                return null;
            }
        }
    }


    /**
     * Tells if the current value is Human Readable
     * 
     * @return <code>true</code> if the value is a String, <code>false</code> otherwise
     */
    public boolean isHumanReadable()
    {
        return isHR;
    }


    /**
     * @return The length of the interned value
     */
    public int length()
    {
        if ( isHR )
        {
            return upValue != null ? upValue.length() : 0;
        }
        else
        {
            return upBytes != null ? upBytes.length : 0;

        }
    }
    
    
    /**
     * Apply the AttributeType to this value. Note that this can't be done twice.
     *
     * @param attributeType The AttributeType to apply
     */
    private void apply( AttributeType attributeType ) throws LdapInvalidAttributeValueException
    {
        if ( attributeType == null )
        {
            // No attributeType : the normalized value and the user provided value are the same
            normValue = upValue;
            normBytes = upBytes;
            
            return;
        }

        this.attributeType = attributeType;

        // We first have to normalize the value before we can check its syntax
        // Get the equality matchingRule, if we have one
        MatchingRule equality = attributeType.getEquality();

        if ( equality != null )
        {
            // If we have an Equality MR, we *must* have a normalizer
            Normalizer normalizer = equality.getNormalizer();
            isHR = attributeType.getSyntax().isHumanReadable();
            
            if ( !isHR )
            {
                // No normalization for binary values
                normValue = upValue;
                normBytes = upBytes;
            }
            else
            {
                if ( normalizer != null )
                {
                    if ( upValue != null )
                    {
                        try
                        {
                            normValue = normalizer.normalize( upValue );
                            normBytes = Strings.getBytesUtf8( normValue );
                        }
                        catch ( LdapException ne )
                        {
                            String message = I18n.err( I18n.ERR_04447_CANNOT_NORMALIZE_VALUE, ne.getLocalizedMessage() );
                            LOG.info( message );
                        }
                    }
                    else
                    {
                        normBytes = upBytes;
                    }
                }
                else
                {
                    normValue = upValue;
                    normBytes = upBytes;
        
                    String message = "The '" + attributeType.getName() + "' AttributeType does not have" + " a normalizer";
                    LOG.error( message );
                    throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, message );
                }
            }
        }
        else
        {
            // No MatchingRule, there is nothing we can do but make the normalized value
            // to be a reference on the user provided value
            normValue = upValue;
            normBytes = upBytes;
        }

        // and checks that the value syntax is valid
        if ( !attributeType.isRelaxed() )
        {
            try
            {
                LdapSyntax syntax = attributeType.getSyntax();
    
                // Check the syntax if not in relaxed mode
                if ( ( syntax != null ) && ( !isValid( syntax.getSyntaxChecker() ) ) )
                {
                    String message = I18n.err( I18n.ERR_04473_NOT_VALID_VALUE, upValue, attributeType );
                    LOG.info( message );
                    throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, message );
                }
            }
            catch ( LdapException le )
            {
                String message = I18n.err( I18n.ERR_04447_CANNOT_NORMALIZE_VALUE, le.getLocalizedMessage() );
                LOG.info( message );
                throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, message, le );
            }
        }

        // Rehash the Value now
        h = 0;
        hashCode();
    }
    
    
    /**
     * Gets a comparator using getMatchingRule() to resolve the matching
     * that the comparator is extracted from.
     *
     * @return a comparator associated with the attributeType or null if one cannot be found
     * @throws LdapException if resolution of schema entities fail
     */
    private LdapComparator<?> getLdapComparator() throws LdapException
    {
        if ( attributeType != null )
        {
            MatchingRule mr = attributeType.getEquality();

            if ( mr != null )
            {
                return ( LdapComparator<?> ) mr.getLdapComparator();
            }
        }

        return null;
    }


    /**
     * Serialize the Value into a buffer at the given position.
     * 
     * @param buffer The buffer which will contain the serialized StringValue
     * @param pos The position in the buffer for the serialized value
     * @return The new position in the buffer
     */
    public int serialize( byte[] buffer, int pos )
    {
        // Compute the length : the isHR flag first, the up and norm value presence flags
        int length = 1 + 1 + 1;

        if ( upValue != null )
        {
            // The presence flag, the length and the value
            length += 4 + upBytes.length;
        }

        if ( normValue != null )
        {
            // The presence flag, the length and the value
            length += 4 + normBytes.length;
        }

        // Check that we will be able to store the data in the buffer
        if ( buffer.length - pos < length )
        {
            throw new ArrayIndexOutOfBoundsException();
        }

        // The STRING flag
        if ( isHR )
        {
            buffer[pos] = Serialize.TRUE;
        }
        else
        {
            buffer[pos] = Serialize.FALSE;
        }
        
        pos++;

        // Write the user provided value, if not null
        if ( upBytes != null )
        {
            buffer[pos++] = Serialize.TRUE;
            pos = Serialize.serialize( upBytes, buffer, pos );
        }
        else
        {
            buffer[pos++] = Serialize.FALSE;
        }

        // Write the normalized value, if not null
        if ( normValue != null )
        {
            buffer[pos++] = Serialize.TRUE;
            pos = Serialize.serialize( normBytes, buffer, pos );
        }
        else
        {
            buffer[pos++] = Serialize.FALSE;
        }

        return pos;
    }
    
    
    /**
     * Deserialize a Value. It will return a new Value instance.
     * 
     * @param in The input stream
     * @return A new Value instance
     * @throws IOException If the stream can't be read
     * @throws ClassNotFoundException If we can't instanciate a Value
     * @throws LdapInvalidAttributeValueException 
     */
    public static Value deserialize( ObjectInput in ) throws IOException, ClassNotFoundException, LdapInvalidAttributeValueException
    {
        Value value = new Value( ( AttributeType ) null );
        value.readExternal( in );

        return value;
    }

    
    /**
     * Deserialize a Value. It will return a new Value instance.
     * 
     * @param attributeType The AttributeType associated with the Value. Can be null
     * @param in The input stream
     * @return A new Value instance
     * @throws IOException If the stream can't be read
     * @throws ClassNotFoundException If we can't instanciate a Value
     * @throws LdapInvalidAttributeValueException 
     */
    public static Value deserialize( AttributeType attributeType, ObjectInput in ) throws IOException, ClassNotFoundException
    {
        Value value = new Value( attributeType );
        value.readExternal( in );

        return value;
    }


    /**
     * Deserialize a StringValue from a byte[], starting at a given position
     * 
     * @param buffer The buffer containing the StringValue
     * @param pos The position in the buffer
     * @return The new position
     * @throws IOException If the serialized value is not a StringValue
     * @throws LdapInvalidAttributeValueException 
     */
    public int deserialize( byte[] buffer, int pos ) throws IOException, LdapInvalidAttributeValueException
    {
        if ( ( pos < 0 ) || ( pos >= buffer.length ) )
        {
            throw new ArrayIndexOutOfBoundsException();
        }

        // Read the isHR flag
        isHR = Serialize.deserializeBoolean( buffer, pos );
        pos++;

        // Read the user provided value, if it's not null
        boolean hasUpValue = Serialize.deserializeBoolean( buffer, pos );
        pos++;

        if ( hasUpValue )
        {
            upBytes = Serialize.deserializeBytes( buffer, pos );
            pos += 4 + upBytes.length;
            upValue = Strings.utf8ToString( upBytes );
        }

        // Read the normalized value, if not null
        boolean hasNormalizedValue = Serialize.deserializeBoolean( buffer, pos );
        pos++;

        if ( hasNormalizedValue )
        {
            normBytes = Serialize.deserializeBytes( buffer, pos );
            pos += 4 + normBytes.length;
            normValue = Strings.utf8ToString( normBytes );
        }

        apply( attributeType );

        return pos;
    }
    
    
    /**
     * {@inheritDoc}
     */
    public void readExternal( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        // Read the isHR flag
        isHR = in.readBoolean();

        if ( isHR )
        {
            // This is a String value 
            // Read the upValue if any
            if ( in.readBoolean() )
            {
                upValue = in.readUTF();
                upBytes = Strings.getBytesUtf8( upValue );
            }

            // Check if we have a normalized value
            if ( in.readBoolean() )
            {
                // Read it if not null
                if ( in.readBoolean() )
                {
                    normValue = in.readUTF();
                    normBytes = Strings.getBytesUtf8( normValue );
                }
            }
        }
        else
        {
            // This is a binary value
            // Read the upvalue length
            int upLength = in.readInt();

            if ( upLength >= 0 )
            {
                upBytes = new byte[upLength];

                in.readFully( upBytes );
            }
        }
        
        // Apply the AttributeType now
        try
        {
            apply( attributeType );
        }
        catch ( LdapInvalidAttributeValueException e )
        {
            // Make the nomValue equals to the upValue
            normValue = upValue;
            normBytes = upBytes;
        }
        
        // And rehash if needed
        if ( h == 0 )
        {
            h = hashCode();
        }
    }


    /**
     * {@inheritDoc}
     */
    public void writeExternal( ObjectOutput out ) throws IOException
    {
        // Write a boolean for the HR flag
        out.writeBoolean( isHR );

        if ( isHR )
        {
            // We first write the upValue, if we have one
            if ( upValue != null )
            {
                out.writeBoolean( true );
                out.writeUTF( upValue );
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
                if ( normValue != null )
                {
                    out.writeBoolean( true );
                    out.writeUTF( normValue );
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
        }
        else
        {
            // This is a binary value, we just have to write the upBytes
            if ( upBytes != null )
            {
                out.writeInt( upBytes.length );

                if ( upBytes.length > 0 )
                {
                    out.write( upBytes, 0, upBytes.length );
                }
            }
            else
            {
                // Null value will be marked with a negative value
                out.writeInt( -1 );
            }
            
        }

        // and flush the data
        out.flush();
    }

    
    /**
     * Compare two values.
     * 
     * @throws IllegalStateException on failures to extract the comparator, or the
     * normalizers needed to perform the required comparisons based on the schema
     */
    public int compareTo( Value value )
    {
        // The two values must have the same type
        if ( isHR != value.isHR )
        {
            String msg = I18n.err( I18n.ERR_04443, this, value );
            LOG.error( msg );
            throw new IllegalStateException( msg );
        }
        
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
        
        if ( !isHR )
        {
            return Strings.compare( normBytes, value.normBytes );
        }

        if ( attributeType != null )
        {
            if ( value.getAttributeType() == null )
            {
                return normValue.compareTo( value.normValue );
            }
            else
            {
                if ( !attributeType.equals( value.attributeType ) )
                {
                    String message = I18n.err( I18n.ERR_04128, toString(), value.getClass() );
                    LOG.error( message );
                    throw new NotImplementedException( message );
                }
            }
        }
        else
        {
            return normValue.compareTo( value.normValue );
        }

        try
        {
            return ( ( LdapComparator<String> ) getLdapComparator() ).compare( normValue, value.getNormValue() );
        }
        catch ( LdapException e )
        {
            String msg = I18n.err( I18n.ERR_04443, this, value );
            LOG.error( msg, e );
            throw new IllegalStateException( msg, e );
        }
    }
    
    
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
            h = Arrays.hashCode( normBytes );
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

        if ( !( obj instanceof Value ) )
        {
            return false;
        }

        Value other = ( Value ) obj;

        // Check if the values aren't of the same type
        if ( isHR != other.isHR )
        {
            // Both values must be HR or not HR
            return false;
        }

        // Ok, now, let's see if we have an AttributeType at all
        if ( attributeType == null )
        {
            if ( other.attributeType != null )
            {
                // Use the comparator
                // We have an AttributeType, we use the associated comparator
                try
                {
                    Comparator comparator = other.getLdapComparator();
                    
                    if ( other.attributeType.getEquality() == null )
                    {
                        return false;
                    }
                    
                    Normalizer normalizer = other.attributeType.getEquality().getNormalizer();

                    if ( normalizer == null )
                    {
                        if ( comparator == null )
                        {
                            return normValue.equals( other.normValue );
                        }
                        else
                        {
                            return comparator.compare( normValue, other.normValue ) == 0;
                        }
                    }
                    
                    String thisNormValue = normalizer.normalize( normValue );
                        
                    // Compare normalized values
                    if ( comparator == null )
                    {
                        return thisNormValue.equals( other.normValue );
                    }
                    else
                    {
                        return comparator.compare( thisNormValue, other.normValue ) == 0;
                    }
                }
                catch ( LdapException ne )
                {
                    return false;
                }
            }
            
            // No attributeType
            if ( isHR )
            {
                if ( normValue == null )
                {
                    return other.normValue == null;
                }
                else
                {
                    return normValue.equals( other.normValue );
                }
            }
            else
            {
                return Arrays.equals( normBytes, other.normBytes );
            }
        }
        else
        {
            if ( other.attributeType == null )
            {
                if ( isHR )
                {
                    // Use the comparator
                    // We have an AttributeType, we use the associated comparator
                    try
                    {
                        Comparator comparator = getLdapComparator();
                        
                        if ( attributeType.getEquality() == null )
                        {
                            return false;
                        }
                        
                        Normalizer normalizer = attributeType.getEquality().getNormalizer();

                        if ( normalizer == null )
                        {
                            if ( comparator == null )
                            {
                                return normValue.equals( other.normValue );
                            }
                            else
                            {
                                return comparator.compare( normValue, other.normValue ) == 0;
                            }
                        }
                        
                        String otherNormValue = normalizer.normalize( other.normValue );
                            
                        // Compare normalized values
                        if ( comparator == null )
                        {
                            return normValue.equals( otherNormValue );
                        }
                        else
                        {
                            return comparator.compare( normValue, otherNormValue ) == 0;
                        }
                    }
                    catch ( LdapException ne )
                    {
                        return false;
                    }
                }
                else
                {
                    return Arrays.equals( normBytes, other.normBytes );
                }
            }

            if ( !attributeType.equals( other.attributeType ) )
            {
                return false;
            }
            
            if ( isHR )
            {
                // Use the comparator
                // We have an AttributeType, we use the associated comparator
                try
                {
                    Comparator comparator = getLdapComparator();

                    // Compare normalized values
                    if ( comparator == null )
                    {
                        return normValue.equals( other.normValue );
                    }
                    else
                    {
                        return comparator.compare( normValue, other.normValue ) == 0;
                    }
                }
                catch ( LdapException ne )
                {
                    return false;
                }
            }
            else
            {
                return Arrays.equals( normBytes, other.normBytes );
            }
        }
    }


    /**
     * @see Object#toString()
     */
    public String toString()
    {
        if ( isHR )
        {
            return upValue == null ? "null" : upValue;
        }
        else
        {
             // Dumps binary in hex with label.
            if ( normBytes == null )
            {
                return "null";
            }
            else if ( normBytes.length > 16 )
            {
                // Just dump the first 16 bytes...
                byte[] copy = new byte[16];

                System.arraycopy( normBytes, 0, copy, 0, 16 );

                return Strings.dumpBytes( copy ) + "...";
            }
            else
            {
                return Strings.dumpBytes( normBytes );
            }
        }
    }
}
