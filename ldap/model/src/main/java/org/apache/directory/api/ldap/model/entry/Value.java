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

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.ldap.model.schema.comparators.StringComparator;
import org.apache.directory.api.ldap.model.schema.normalizers.NoOpNormalizer;
import org.apache.directory.api.util.Serialize;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Class for wrapping attribute values stored into an Entry Attribute, or a AVA.
 * 
 * We keep the value as byte[] unless we need to convert them to a String (if we have
 * a HR Value).
 * 
 * The serialized Value will be stored as :
 * 
 * <pre>
 *  +---------+
 *  | boolean | isHR flag
 *  +---------+
 *  | boolean | TRUE if the value is not null, FALSE otherwise
 *  +---------+
 * [|   int   |]  If the previous flag is TRUE, the length of the value
 * [+---------+]
 * [| byte[]  |] The value itself
 * [+---------+]
 *  | boolean | TRUE if we have a prepared String
 *  +---------+
 * [| String  |] The prepared String if we have it
 * [+---------+]
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class Value implements Cloneable, Externalizable, Comparable<Value>
{
    /** Used for serialization */
    private static final long serialVersionUID = 2L;

    /** logger for reporting errors that might not be handled properly upstream */
    private static final Logger LOG = LoggerFactory.getLogger( Value.class );

    /** reference to the attributeType associated with the value */
    private transient AttributeType attributeType;

    /** the User Provided value if it's a String */
    private String upValue;

    /** the prepared representation of the user provided value if it's a String */
    private String normValue;

    /** The computed hashcode. We don't want to compute it each time the hashcode() method is called */
    private volatile int h;

    /** The UTF-8 bytes for this value (we use the UP value) */
    private byte[] bytes;

    /** Two flags used to tell if the value is HR or not in serialization */
    private boolean isHR = true;
    
    /** A default comparator if we don't have an EQUALITY MR */
    private static StringComparator stringComparator = new StringComparator( null );
    
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------
    /**
     * Creates a Value with an initial user provided String value.
     *
     * @param upValue the value to wrap. It can be null
     */
    public Value( String upValue )
    {
        this.upValue = upValue;
        
        // We can't normalize the value, we store it as is
        normValue = upValue;
        
        if ( upValue != null )
        {
            bytes = Strings.getBytesUtf8( upValue );
        }
        
        hashCode();
    }
    
    
    /**
     * Creates a Value with an initial user provided binary value.
     *
     * @param value the binary value to wrap which may be null, or a zero length byte array
     */
    public Value( byte[] value )
    {
        if ( value != null )
        {
            bytes = new byte[value.length];
            System.arraycopy( value, 0, bytes, 0, value.length );
        }
        else
        {
            bytes = null;
        }
        
        isHR = false;

        hashCode();
    }


    /**
     * Creates a schema aware binary Value with an initial value.
     *
     * @param attributeType the schema type associated with this Value
     * @param upValue the value to wrap
     * @throws LdapInvalidAttributeValueException If the added value is invalid accordingly
     * to the schema
     */
    public Value( AttributeType attributeType, byte[] upValue ) throws LdapInvalidAttributeValueException
    {
        init( attributeType );
        
        if ( upValue != null )
        {
            bytes = new byte[upValue.length];
            System.arraycopy( upValue, 0, bytes, 0, upValue.length );

            if ( isHR )
            {
                this.upValue = Strings.utf8ToString( upValue );
            }
        }
        else
        {
            bytes = null;
        }
        
        if ( ( attributeType != null ) && !attributeType.isRelaxed() )
        {
            // Check the value
            SyntaxChecker syntaxChecker = attributeType.getSyntax().getSyntaxChecker();

            if ( syntaxChecker != null )
            {
                if ( !syntaxChecker.isValidSyntax( bytes ) )
                {
                    throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, 
                        I18n.err( I18n.ERR_13246_INVALID_VALUE_PER_SYNTAX ) );
                }
            }
            else
            {
                // We should always have a SyntaxChecker
                throw new IllegalArgumentException( I18n.err( I18n.ERR_13219_NULL_SYNTAX_CHECKER, normValue ) );
            }
        }

        hashCode();
    }
    
    
    private void init( AttributeType attributeType )
    {
        if ( attributeType != null )
        {
            if ( attributeType.getSyntax() == null )
            {
                // Some broken LDAP servers do not have proper syntax definitions, default to HR
                LOG.info( I18n.err( I18n.ERR_13225_NO_SYNTAX ) );
                isHR = true;
                //throw new IllegalArgumentException( I18n.err( I18n.ERR_13225_NO_SYNTAX ) );
            }
            else
            {
                isHR = attributeType.getSyntax().isHumanReadable();
            }
        }
        else
        {
            LOG.warn( I18n.msg( I18n.MSG_13202_AT_IS_NULL ) );
        }
        
        this.attributeType = attributeType;
    }


    /**
     * Creates a schema aware binary Value with an initial value. This method is
     * only to be used by deserializers.
     *
     * @param attributeType the schema type associated with this Value
     * @param value the value to wrap
     */
    /* Package protected*/ Value( AttributeType attributeType )
    {
        init( attributeType );
    }
    
    
    /**
     * Creates a schema aware StringValue with an initial user provided String value.
     *
     * @param attributeType the schema type associated with this StringValue
     * @param upValue the value to wrap
     * @throws LdapInvalidAttributeValueException If the added value is invalid accordingly
     * to the schema
     */
    public Value( AttributeType attributeType, String upValue ) throws LdapInvalidAttributeValueException
    {
        init( attributeType );
        this.upValue = upValue;
        
        if ( upValue != null )
        {
            bytes = Strings.getBytesUtf8( upValue );
        }
        else
        {
            bytes = null;
        }
        
        try
        {
            computeNormValue();
        }
        catch ( LdapException le )
        {
            LOG.error( le.getMessage() );
            throw new IllegalArgumentException( I18n.err( I18n.ERR_13247_INVALID_VALUE_CANT_NORMALIZE ) );
        }
        
        if ( !attributeType.isRelaxed() )
        {
            // Check the value
            if ( attributeType.getSyntax().getSyntaxChecker() != null )
            {
                if ( !attributeType.getSyntax().getSyntaxChecker().isValidSyntax( upValue ) )
                {
                    throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, 
                        I18n.err( I18n.ERR_13246_INVALID_VALUE_PER_SYNTAX ) );
                }
            }
            else
            {
                // We should always have a SyntaxChecker
                throw new IllegalArgumentException( I18n.err( I18n.ERR_13219_NULL_SYNTAX_CHECKER, normValue ) );
            }
        }
        
        hashCode();
    }
    
    
    /**
     * Creates a schema aware StringValue with an initial user provided String value and 
     * its normalized Value
     *
     * @param attributeType the schema type associated with this StringValue
     * @param upValue the value to wrap
     * @param normValue the normalized value to wrap
     * @throws LdapInvalidAttributeValueException If the added value is invalid accordingly
     * to the schema
     */
    public Value( AttributeType attributeType, String upValue, String normValue ) throws LdapInvalidAttributeValueException
    {
        init( attributeType );
        this.upValue = upValue;
        
        if ( upValue != null )
        {
            bytes = Strings.getBytesUtf8( upValue );
        }
        else
        {
            bytes = null;
        }
        
        this.normValue = normValue;
        
        if ( !attributeType.isRelaxed() )
        {
            // Check the value
            if ( attributeType.getSyntax().getSyntaxChecker() != null )
            {
                if ( !attributeType.getSyntax().getSyntaxChecker().isValidSyntax( upValue ) )
                {
                    throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, 
                        I18n.err( I18n.ERR_13246_INVALID_VALUE_PER_SYNTAX ) );
                }
            }
            else
            {
                // We should always have a SyntaxChecker
                throw new IllegalArgumentException( I18n.err( I18n.ERR_13219_NULL_SYNTAX_CHECKER, normValue ) );
            }
        }
        
        hashCode();
    }


    /**
     * Creates a Value from an existing Value with an AttributeType
     *
     * @param attributeType the schema attribute type associated with this StringValue
     * @param value the original Value
     * @throws LdapInvalidAttributeValueException If the value is invalid
     */
    public Value( AttributeType attributeType, Value value ) throws LdapInvalidAttributeValueException
    {
        init( attributeType );
        
        if ( isHR )
        {
            this.upValue = value.upValue;
        }

        try
        {
            computeNormValue();
        }
        catch ( LdapException le )
        {
            LOG.error( le.getMessage() );
            throw new IllegalArgumentException( I18n.err( I18n.ERR_13247_INVALID_VALUE_CANT_NORMALIZE ) );
        }
        
        // Check the normValue
        if ( !attributeType.isRelaxed() )
        {
            // Check the value
            if ( attributeType.getSyntax().getSyntaxChecker() != null )
            {
                attributeType.getSyntax().getSyntaxChecker().isValidSyntax( value.normValue );
            }
            else
            {
                // We should always have a SyntaxChecker
                throw new IllegalArgumentException( I18n.err( I18n.ERR_13219_NULL_SYNTAX_CHECKER, normValue ) );
            }
        }
            
        // We have to copy the byte[], they are just referenced by suoer.clone()
        if ( value.bytes != null )
        {
            bytes = new byte[value.bytes.length];
            System.arraycopy( value.bytes, 0, bytes, 0, value.bytes.length );
        }

        hashCode();
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
        return new Value( attributeType );
    }
    

    /**
     * Clone a Value
     * 
     * @return A cloned value
     */
    @Override
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
                if ( bytes != null )
                {
                    clone.bytes = new byte[bytes.length];
                    System.arraycopy( bytes, 0, clone.bytes, 0, bytes.length );
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
            return upValue == null;
        }
        else
        {
            return bytes == null;
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
     * Get the User Provided value. If the value is Human Readable, it will return
     * a String, otherwise it returns null.
     *
     * @return The user provided value
     */
    public String getValue()
    {
        if ( isHR )
        {
            return upValue;
        }
        else
        {
            return Strings.utf8ToString( bytes );
        }
    }


    /**
     * Compute the normalized value
     * 
     * @throws LdapException If we were'nt able to normalize the value
     */
    private void computeNormValue() throws LdapException
    {
        if ( upValue == null )
        {
            return;
        }
        
        Normalizer normalizer;
        
        // We should have a Equality MatchingRule
        MatchingRule equality = attributeType.getEquality();
        
        if ( equality == null )
        {
            // Let's try with the Substring MatchingRule
            MatchingRule subString = attributeType.getSubstring();
            
            if ( subString == null )
            {
                // last chance : ordering matching rule
                MatchingRule ordering = attributeType.getOrdering();
                
                if ( ordering == null )
                {
                    // Ok, no luck. Use a NoOp normalizer
                    normalizer = new NoOpNormalizer();
                }
                else
                {
                    normalizer = ordering.getNormalizer();
                }
            }
            else
            {
                normalizer = subString.getNormalizer();
            }
        }
        else
        {
            normalizer = equality.getNormalizer();
        }
        
        if ( normalizer == null )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_13220_NO_NORMALIZER ) );
        }

        // Now, normalize the upValue
        normValue = normalizer.normalize( upValue );
    }
    
    
    /**
     * @return The normalized value
     */
    public String getNormalized()
    {
        return normValue;
    }


    /**
     * Get the wrapped value as a byte[]. If the original value
     * is binary, this method will return a copy of the wrapped byte[]
     *
     * @return the wrapped value as a byte[]
     */
    public byte[] getBytes()
    {
        if ( bytes == null )
        {
            return null;
        }
        
        if ( bytes.length == 0 )
        {
            return Strings.EMPTY_BYTES;
        }
        
        byte[] copy = new byte[bytes.length];
        System.arraycopy( bytes, 0, copy, 0, bytes.length );
        
        return copy;
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
     * @param syntaxChecker the SyntaxChecker to use to validate the value
     * @return <code>true</code> if the value is valid
     * @exception LdapInvalidAttributeValueException if the value cannot be validated
     */
    public final boolean isValid( SyntaxChecker syntaxChecker ) throws LdapInvalidAttributeValueException
    {
        if ( syntaxChecker == null )
        {
            String message = I18n.err( I18n.ERR_13219_NULL_SYNTAX_CHECKER, toString() );
            LOG.error( message );
            throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, message );
        }

        // No attributeType, or it's in relaxed mode
        if ( isHR )
        {
            // We need to prepare the String in this case
            return syntaxChecker.isValidSyntax( getValue() );
        }
        else
        {
            return syntaxChecker.isValidSyntax( bytes );
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
            return bytes != null ? bytes.length : 0;
        }
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
                return mr.getLdapComparator();
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
        // Compute the length : the isHR flag first, the value and prepared value presence flags
        int length = 1;
        byte[] preparedBytes = null;

        if ( isHR )
        { 
            if ( upValue != null )
            {
                // The presence flag, the length and the value
                length += 1 + 4 + bytes.length;
            }

            if ( normValue != null )
            {
                // The presence flag, the length and the value
                preparedBytes = Strings.getBytesUtf8( normValue );
                length += 1 + 4 + preparedBytes.length;
            }
        }
        else
        {
            if ( bytes != null )
            {
                length = 1 + 1 + 4 + bytes.length;
            }
            else
            {
                length = 1 + 1;
            }
        }

        // Check that we will be able to store the data in the buffer
        if ( buffer.length - pos < length )
        {
            throw new ArrayIndexOutOfBoundsException();
        }

        if ( isHR )
        {
            buffer[pos++] = Serialize.TRUE;

            // Write the user provided value, if not null
            if ( bytes != null )
            {
                buffer[pos++] = Serialize.TRUE;
                pos = Serialize.serialize( bytes, buffer, pos );
            }
            else
            {
                buffer[pos++] = Serialize.FALSE;
            }
    
            // Write the prepared value, if not null
            if ( normValue != null )
            {
                buffer[pos++] = Serialize.TRUE;
                pos = Serialize.serialize( preparedBytes, buffer, pos );
            }
            else
            {
                buffer[pos++] = Serialize.FALSE;
            }
        }
        else
        {
            buffer[pos++] = Serialize.FALSE;

            if ( bytes != null )
            {
                buffer[pos++] = Serialize.TRUE;
                pos = Serialize.serialize( bytes, buffer, pos );
            }
            else
            {
                buffer[pos++] = Serialize.FALSE;
            }
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
     * @throws LdapInvalidAttributeValueException If the value is invalid
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
     * @throws LdapInvalidAttributeValueException If the value is invalid
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

        if ( isHR )
        {
            // Read the user provided value, if it's not null
            boolean hasValue = Serialize.deserializeBoolean( buffer, pos );
            pos++;
    
            if ( hasValue )
            {
                bytes = Serialize.deserializeBytes( buffer, pos );
                pos += 4 + bytes.length;

                upValue = Strings.utf8ToString( bytes );
            }

            // Read the prepared value, if not null
            boolean hasPreparedValue = Serialize.deserializeBoolean( buffer, pos );
            pos++;
    
            if ( hasPreparedValue )
            {
                byte[] preparedBytes = Serialize.deserializeBytes( buffer, pos );
                pos += 4 + preparedBytes.length;
                normValue = Strings.utf8ToString( preparedBytes );
            }
        }
        else
        {
            // Read the user provided value, if it's not null
            boolean hasBytes = Serialize.deserializeBoolean( buffer, pos );
            pos++;
    
            if ( hasBytes )
            {
                bytes = Serialize.deserializeBytes( buffer, pos );
                pos += 4 + bytes.length;
            }

        }
        
        if ( attributeType != null )
        {
            try
            {
                computeNormValue();
            }
            catch ( LdapException le )
            {
                throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, le.getMessage() );
            }
        }
        
        hashCode();

        return pos;
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void readExternal( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        // Read the isHR flag
        isHR = in.readBoolean();

        if ( isHR )
        {
            // Read the value if any
            if ( in.readBoolean() )
            {
                int length = in.readInt();
                bytes = new byte[length];
                
                if ( length != 0 )
                {
                    in.readFully( bytes );
                }
    
                upValue = Strings.utf8ToString( bytes );
            }
    
            // Read the prepared String if any
            if ( in.readBoolean() )
            {
                normValue = in.readUTF();
            }
        }
        else
        {
            if ( in.readBoolean() )
            {
                int length = in.readInt();
                bytes = new byte[length];
                
                if ( length != 0 )
                {
                    in.readFully( bytes );
                }
            }
        }
        
        hashCode();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void writeExternal( ObjectOutput out ) throws IOException
    {
        // Write a boolean for the HR flag
        out.writeBoolean( isHR );

        if ( isHR )
        { 
            // Write the value if any
            out.writeBoolean( upValue != null );
    
            if ( upValue != null )
            {
                // Write the value
                out.writeInt( bytes.length );
    
                if ( bytes.length > 0 )
                {
                    out.write( bytes );
                }
            }

            // Write the prepared value if any
            out.writeBoolean( normValue != null );
    
            if ( normValue != null )
            {
                // Write the value
                out.writeUTF( normValue );
            }
        }
        else
        {
            // Just write the bytes if not null
            out.writeBoolean( bytes != null );

            if ( bytes != null )
            {
                out.writeInt( bytes.length );
                
                if ( bytes.length > 0 )
                {
                    out.write( bytes );
                }
            }
        }

        // and flush the data
        out.flush();
    }

    
    /**
     * Compare the current value with a String.
     * 
     * @param other the String we want to compare the current value with
     * @return a positive value if the current value is above the provided String, a negative value
     * if it's below, 0 if they are equal.
     * @throws IllegalStateException on failures to extract the comparator, or the
     * normalizers needed to perform the required comparisons based on the schema
     */
    public int compareTo( String other )
    {
        if ( !isHR )
        {
            String msg = I18n.err( I18n.ERR_13224_FAILED_TO_COMPARE_NORM_VALUES, this, other );
            LOG.error( msg );
            throw new IllegalStateException( msg );
        }
        
        // Check if both value are null
        if ( bytes == null )
        {
            if ( other == null )
            {
                return 0;
            }
            else
            {
                return -1;
            }
        }
        else if ( other == null )
        {
            return 1;
        }
        
        // We have HR values. We may have an attributeType for the base Value
        // It actually does not matter if the second value has an attributeType
        // which is different
        try
        {
            if ( attributeType != null )
            {
                // No normalization. Use the base AttributeType to normalize
                // the other value
                String normalizedOther = attributeType.getEquality().getNormalizer().normalize( other );
                
                return normValue.compareTo( normalizedOther );
            }
            else
            {
                // No AtributeType... Compare the normValue
                return normValue.compareTo( other );
            }
        }
        catch ( LdapException le )
        {
            return -1;
        }
    }

    
    /**
     * Compare two values. We compare the stored bytes
     * 
     * @param other the byte[] we want to compare the current value with
     * @return a positive value if the current value is above the provided byte[], a negative value
     * if it's below, 0 if they are equal.
     * @throws IllegalStateException on failures to extract the comparator, or the
     * normalizers needed to perform the required comparisons based on the schema
     */
    public int compareTo( byte[] other )
    {
        if ( isHR )
        {
            String msg = I18n.err( I18n.ERR_13224_FAILED_TO_COMPARE_NORM_VALUES, this, other );
            LOG.error( msg );
            throw new IllegalStateException( msg );
        }
        
        // Check if both value are null
        if ( bytes == null )
        {
            if ( other == null )
            {
                return 0;
            }
            else
            {
                return -1;
            }
        }
        else if ( other == null )
        {
            return 1;
        }

        // Default : compare the bytes
        return Strings.compare( bytes, other );
    }

    
    /**
     * Compare two values. We either compare the stored bytes, or we use the 
     * AttributeType Comparator, if we have an Ordered MatchingRule. 
     * 
     * @param other The other Value we want to compare the current value with
     * @return a positive value if the current value is above the provided value, a negative value
     * if it's below, 0 if they are equal.
     * @throws IllegalStateException on failures to extract the comparator, or the
     * normalizers needed to perform the required comparisons based on the schema
     */
    @Override
    public int compareTo( Value other )
    {
        // The two values must have the same type
        if ( isHR != other.isHR )
        {
            String msg = I18n.err( I18n.ERR_13224_FAILED_TO_COMPARE_NORM_VALUES, this, other );
            LOG.error( msg );
            throw new IllegalStateException( msg );
        }
        
        // Check if both value are null
        if ( bytes == null )
        {
            if ( other.bytes == null )
            {
                return 0;
            }
            else
            {
                return -1;
            }
        }
        else if ( other.bytes == null )
        {
            return 1;
        }
        
        // Ok, neither this nor the other have null values.
        
        // Shortcut when the value are not HR
        if ( !isHR )
        {
            return Strings.compare( bytes, other.bytes );
        }

        // We have HR values. We may have an attributeType for the base Value
        // It actually does not matter if the second value has an attributeType
        // which is different
        try
        {
            if ( attributeType != null )
            {
                // Check if the other value has been normalized or not
                if ( other.attributeType == null )
                {
                    // No normalization. Use the base AttributeType to normalize
                    // the other value
                    String normalizedOther = attributeType.getEquality().getNormalizer().normalize( other.upValue );
                    
                    return normValue.compareTo( normalizedOther );
                }
                else
                {
                    return normValue.compareTo( other.normValue );
                }
            }
            else
            {
                if ( other.attributeType != null )
                {
                    // Normalize the current value with the other value normalizer
                    String normalizedThis = other.attributeType.getEquality().getNormalizer().normalize( upValue );
                    
                    return normalizedThis.compareTo( other.normValue );
                }
                else
                {
                    // No AtributeType... Compare the normValue
                    return normValue.compareTo( other.normValue );
                }
            }
        }
        catch ( LdapException le )
        {
            return -1;
        }
    }
    
    
    /**
     * We compare two values using their Comparator, if any. 
     * 
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals( Object obj )
    {
        if ( this == obj )
        {
            return true;
        }

        if ( obj instanceof String )
        {
            String other = ( String ) obj;
            
            if ( !isHR )
            {
                return false;
            }
            
            if ( attributeType == null )
            {
                if ( upValue != null )
                {
                    return upValue.equals( other );
                }
                else
                {
                    return obj == null;
                }
            }
            else
            {
                // Use the comparator
                // We have an AttributeType, we use the associated comparator
                try
                {
                    LdapComparator<String> comparator = ( LdapComparator<String> ) getLdapComparator();
                    
                    Normalizer normalizer = null;
                    
                    if ( attributeType.getEquality() != null )
                    {
                        normalizer = attributeType.getEquality().getNormalizer();
                    }

                    if ( normalizer == null )
                    {
                        if ( comparator == null )
                        {
                            return normValue.equals( other );
                        }
                        else
                        {
                            return comparator.compare( normValue, other ) == 0;
                        }
                    }
                    
                    String thisNormValue = normValue;
                    String otherNormValue = normalizer.normalize( other );
                        
                    // Compare normalized values
                    if ( comparator == null )
                    {
                        return thisNormValue.equals( otherNormValue );
                    }
                    else
                    {
                        return comparator.compare( thisNormValue, otherNormValue ) == 0;
                    }
                }
                catch ( LdapException ne )
                {
                    return false;
                }
            }
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
        
        if ( !isHR )
        {
            // Shortcut for binary values
            return Arrays.equals( bytes, other.bytes );
        }
        
        // HR values
        if ( bytes == null )
        {
            return other.bytes == null;
        }
        
        // Special case
        if ( other.bytes == null )
        {
            return false;
        }
        
        // Not null, but empty. We try to avoid a spurious String Preparation
        if ( bytes.length == 0 )
        {
            return other.bytes.length == 0;
        }
        else if ( other.bytes.length == 0 )
        {
            return false;
        }

        // Ok, now, let's see if we have an AttributeType at all. If both have one,
        // and if they aren't equal, then we get out. If one of them has an AttributeType and
        // not the other, we will assume that this is the AttributeType to use.
        MatchingRule equalityMR;
        
        if ( attributeType == null )
        {
            if ( other.attributeType != null )
            {
                // Use the Other value AT
                equalityMR = other.attributeType.getEquality();
 
                // We may not have an Equality MR, and in tjis case, we compare the bytes
                if ( equalityMR == null )
                {
                    return Arrays.equals( bytes, other.bytes );
                }
                
                LdapComparator<Object> ldapComparator = equalityMR.getLdapComparator();
                
                if ( ldapComparator == null )
                {
                    // This is an error !
                    LOG.error( I18n.err( I18n.ERR_13249_NO_COMPARATOR_FOR_AT, other.attributeType ) );
                    
                    return false;
                }
                
                return ldapComparator.compare( normValue, other.normValue ) == 0;
            }
            else
            {
                // Both are null. We will compare the prepared String if we have one, 
                // or the bytes otherwise.
                if ( upValue != null )
                {
                    return upValue.equals( other.upValue );
                }
                else
                {
                    return Arrays.equals( bytes, other.bytes );
                } 
            }
        }
        else 
        {
            if ( other.attributeType != null )
            {
                // Both attributeType must be equal
                if ( !attributeType.equals( other.attributeType ) )
                {
                    return false;
                }
                
                // Use the comparator
                // We have an AttributeType, we use the associated comparator
                try
                {
                    LdapComparator<String> comparator = ( LdapComparator<String> ) getLdapComparator();
                    
                    if ( other.attributeType.getEquality() == null )
                    {
                        // No equality ? Default to comparing using a String comparator
                        return stringComparator.compare( normValue, other.normValue ) == 0;
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
            if ( normValue == null )
            {
                return other.normValue == null;
            }
            else
            {
                return normValue.equals( other.normValue );
            }
        }
    }

    
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
            // stored in an attribute - the binary version does the same
            if ( isHR )
            {
                if ( normValue != null )
                {
                    h = normValue.hashCode();
                }
                else
                {
                    h = 0;
                }
            }
            else
            {
                h = Arrays.hashCode( bytes );
            }
        }

        return h;
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        if ( isHR )
        {
            return upValue == null ? "null" : upValue;
        }
        else
        {
             // Dumps binary in hex with label.
            if ( bytes == null )
            {
                return "null";
            }
            else if ( bytes.length > 16 )
            {
                // Just dump the first 16 bytes...
                byte[] copy = new byte[16];

                System.arraycopy( bytes, 0, copy, 0, 16 );

                return Strings.dumpBytes( copy ) + "...";
            }
            else
            {
                return Strings.dumpBytes( bytes );
            }
        }
    }
}
