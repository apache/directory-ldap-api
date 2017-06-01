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
package org.apache.directory.api.ldap.model.name;


import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.entry.BinaryValue;
import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Serialize;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Attribute Type And Value, which is the basis of all Rdn. It contains a
 * type, and a value. The type must not be case sensitive. Superfluous leading
 * and trailing spaces MUST have been trimmed before. The value MUST be in UTF8
 * format, according to RFC 2253. If the type is in OID form, then the value
 * must be a hexadecimal string prefixed by a '#' character. Otherwise, the
 * string must respect the RC 2253 grammar.
 *
 * We will also keep a User Provided form of the AVA (Attribute Type And Value),
 * called upName.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class Ava implements Externalizable, Cloneable, Comparable<Ava>
{
    /**
     * Declares the Serial Version Uid.
     *
     * @see <a
     *      href="http://c2.com/cgi/wiki?AlwaysDeclareSerialVersionUid">Always
     *      Declare Serial Version Uid</a>
     */
    private static final long serialVersionUID = 1L;

    /** The LoggerFactory used by this class */
    private static final Logger LOG = LoggerFactory.getLogger( Ava.class );

    /** The normalized Name type */
    private String normType;

    /** The user provided Name type */
    private String upType;

    /** The value. It can be a String or a byte array */
    private Value<?> value;

    /** The user provided Ava */
    private String upName;

    /** The attributeType if the Ava is schemaAware */
    private AttributeType attributeType;

    /** the schema manager */
    private SchemaManager schemaManager;

    /** The computed hashcode */
    private volatile int h;


    /**
     * Constructs an empty Ava
     */
    public Ava()
    {
        this( null );
    }


    /**
     * Constructs an empty schema aware Ava.
     * 
     * @param schemaManager The SchemaManager instance
     */
    public Ava( SchemaManager schemaManager )
    {
        normType = null;
        upType = null;
        value = null;
        upName = "";
        this.schemaManager = schemaManager;
        this.attributeType = null;
    }


    /**
     * Construct an Ava containing a binary value.
     * <p>
     * Note that the upValue should <b>not</b> be null or empty, or resolve
     * to an empty string after having trimmed it.
     *
     * @param upType The User Provided type
     * @param upValue The User Provided binary value
     * 
     * @throws LdapInvalidDnException If the given type or value are invalid
     */
    public Ava( String upType, byte[] upValue ) throws LdapInvalidDnException
    {
        this( null, upType, upValue );
    }


    /**
     * Construct a schema aware Ava containing a binary value. The AttributeType
     * and value will be normalized accordingly to the given SchemaManager.
     * <p>
     * Note that the upValue should <b>not</b> be null or empty, or resolve
     * to an empty string after having trimmed it.
     *
     * @param schemaManager The SchemaManager instance
     * @param upType The User Provided type
     * @param upValue The User Provided binary value
     * 
     * @throws LdapInvalidDnException If the given type or value are invalid
     */
    public Ava( SchemaManager schemaManager, String upType, byte[] upValue ) throws LdapInvalidDnException
    {
        if ( schemaManager != null )
        {
            this.schemaManager = schemaManager;

            try
            {
                attributeType = schemaManager.lookupAttributeTypeRegistry( upType );
            }
            catch ( LdapException le )
            {
                String message = I18n.err( I18n.ERR_04188 );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message, le );
            }

            try
            {
                createAva( schemaManager, upType, new BinaryValue( attributeType, upValue ) );
            }
            catch ( LdapInvalidAttributeValueException liave )
            {
                String message = I18n.err( I18n.ERR_04188 );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message, liave );
            }
        }
        else
        {
            createAva( upType, new BinaryValue( upValue ) );
        }
    }


    /**
     * Construct an Ava with a String value.
     * <p>
     * Note that the upValue should <b>not</b> be null or empty, or resolve
     * to an empty string after having trimmed it.
     *
     * @param upType The User Provided type
     * @param upValue The User Provided String value
     * 
     * @throws LdapInvalidDnException If the given type or value are invalid
     */
    public Ava( String upType, String upValue ) throws LdapInvalidDnException
    {
        this( null, upType, upValue );
    }


    /**
     * Construct a schema aware Ava with a String value.
     * <p>
     * Note that the upValue should <b>not</b> be null or empty, or resolve
     * to an empty string after having trimmed it.
     *
     * @param schemaManager The SchemaManager instance
     * @param upType The User Provided type
     * @param upValue The User Provided String value
     * 
     * @throws LdapInvalidDnException If the given type or value are invalid
     */
    public Ava( SchemaManager schemaManager, String upType, String upValue ) throws LdapInvalidDnException
    {
        if ( schemaManager != null )
        {
            this.schemaManager = schemaManager;

            try
            {
                attributeType = schemaManager.lookupAttributeTypeRegistry( upType );
            }
            catch ( LdapException le )
            {
                String message = I18n.err( I18n.ERR_04188 );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message, le );
            }

            try
            {
                createAva( schemaManager, upType, new StringValue( attributeType, upValue ) );
            }
            catch ( LdapInvalidAttributeValueException liave )
            {
                String message = I18n.err( I18n.ERR_04188 );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message, liave );
            }
        }
        else
        {
            createAva( upType, new StringValue( upValue ) );
        }
    }


    /**
     * Construct an Ava. The type and value are normalized :
     * <li> the type is trimmed and lowercased </li>
     * <li> the value is trimmed </li>
     * <p>
     * Note that the upValue should <b>not</b> be null or empty, or resolved
     * to an empty string after having trimmed it.
     *
     * @param schemaManager The SchemaManager
     * @param upType The User Provided type
     * @param normType The normalized type
     * @param value The value
     * 
     * @throws LdapInvalidDnException If the given type or value are invalid
     */
    // WARNING : The protection level is left unspecified intentionally.
    // We need this method to be visible from the DnParser class, but not
    // from outside this package.
    /* Unspecified protection */Ava( SchemaManager schemaManager, String upType, String normType, Value<?> value )
        throws LdapInvalidDnException
    {
        this.upType = upType;
        this.normType = normType;
        this.value = value;
        upName = this.upType + '=' + ( this.value == null ? "" : this.value.getString() );

        if ( schemaManager != null )
        {
            apply( schemaManager );
        }

        hashCode();
    }


    /**
     * Construct an Ava. The type and value are normalized :
     * <li> the type is trimmed and lowercased </li>
     * <li> the value is trimmed </li>
     * <p>
     * Note that the upValue should <b>not</b> be null or empty, or resolved
     * to an empty string after having trimmed it.
     *
     * @param upType The User Provided type
     * @param normType The normalized type
     * @param value The User Provided value
     * @param upName The User Provided name (may be escaped)
     * 
     * @throws LdapInvalidDnException If the given type or value are invalid
     */
    // WARNING : The protection level is left unspecified intentionally.
    // We need this method to be visible from the DnParser class, but not
    // from outside this package.
    /* Unspecified protection */Ava( String upType, String normType, Value<?> value, String upName )
        throws LdapInvalidDnException
    {
        this( null, upType, normType, value, upName );
    }
    
    
    /**
     * Construct an Ava. The type and value are normalized :
     * <li> the type is trimmed and lowercased </li>
     * <li> the value is trimmed </li>
     * <p>
     * Note that the upValue should <b>not</b> be null or empty, or resolved
     * to an empty string after having trimmed it.
     *
     * @param attributeType The AttributeType for this value
     * @param upType The User Provided type
     * @param normType The normalized type
     * @param value The value
     * @param upName The User Provided name (may be escaped)
     * 
     * @throws LdapInvalidDnException If the given type or value are invalid
     */
    // WARNING : The protection level is left unspecified intentionally.
    // We need this method to be visible from the DnParser class, but not
    // from outside this package.
    /* Unspecified protection */Ava( AttributeType attributeType, String upType, String normType, Value<?> value, String upName )
        throws LdapInvalidDnException
    {
        this.attributeType = attributeType;
        String upTypeTrimmed = Strings.trim( upType );
        String normTypeTrimmed = Strings.trim( normType );

        if ( Strings.isEmpty( upTypeTrimmed ) )
        {
            if ( Strings.isEmpty( normTypeTrimmed ) )
            {
                String message = I18n.err( I18n.ERR_04188 );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message );
            }
            else
            {
                // In this case, we will use the normType instead
                this.normType = Strings.lowerCaseAscii( normTypeTrimmed );
                this.upType = normType;
            }
        }
        else if ( Strings.isEmpty( normTypeTrimmed ) )
        {
            // In this case, we will use the upType instead
            this.normType = Strings.lowerCaseAscii( upTypeTrimmed );
            this.upType = upType;
        }
        else
        {
            this.normType = Strings.lowerCaseAscii( normTypeTrimmed );
            this.upType = upType;
        }

        this.value = value;
        this.upName = upName;
        hashCode();
    }


    /**
     * Construct a schema aware Ava. The AttributeType and value will be checked accordingly
     * to the SchemaManager.
     * <p>
     * Note that the upValue should <b>not</b> be null or empty, or resolve
     * to an empty string after having trimmed it.
     *
     * @param schemaManager The SchemaManager instance
     * @param upType The User Provided type
     * @param value The value
     * 
     * @throws LdapInvalidDnException If the given type or value are invalid
     */
    private void createAva( SchemaManager schemaManager, String upType, Value<?> value )
        throws LdapInvalidDnException
    {
        normType = attributeType.getOid();
        this.upType = upType;
        this.value = value;
        upName = this.upType + '=' + ( value == null ? "" : Rdn.escapeValue( value.getString() ) );
        hashCode();
    }


    /**
     * Construct an Ava. The type and value are normalized :
     * <li> the type is trimmed and lowercased </li>
     * <li> the value is trimmed </li>
     * <p>
     * Note that the upValue should <b>not</b> be null or empty, or resolved
     * to an empty string after having trimmed it.
     *
     * @param upType The User Provided type
     * @param upValue The User Provided value
     * 
     * @throws LdapInvalidDnException If the given type or value are invalid
     */
    private void createAva( String upType, Value<?> upValue ) throws LdapInvalidDnException
    {
        String upTypeTrimmed = Strings.trim( upType );
        String normTypeTrimmed = Strings.trim( normType );

        if ( Strings.isEmpty( upTypeTrimmed ) )
        {
            if ( Strings.isEmpty( normTypeTrimmed ) )
            {
                String message = I18n.err( I18n.ERR_04188 );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message );
            }
            else
            {
                // In this case, we will use the normType instead
                this.normType = Strings.lowerCaseAscii( normTypeTrimmed );
                this.upType = normType;
            }
        }
        else if ( Strings.isEmpty( normTypeTrimmed ) )
        {
            // In this case, we will use the upType instead
            this.normType = Strings.lowerCaseAscii( upTypeTrimmed );
            this.upType = upType;
        }
        else
        {
            this.normType = Strings.lowerCaseAscii( normTypeTrimmed );
            this.upType = upType;

        }

        value = upValue;

        upName = this.upType + '=' + ( value == null ? "" : Rdn.escapeValue( value.getString() ) );
        hashCode();
    }


    /**
     * Apply a SchemaManager to the Ava. It will normalize the Ava.<br>
     * If the Ava already had a SchemaManager, then the new SchemaManager will be
     * used instead.
     * 
     * @param schemaManager The SchemaManager instance to use
     * @throws LdapInvalidDnException If the Ava can't be normalized accordingly
     * to the given SchemaManager
     */
    public void apply( SchemaManager schemaManager ) throws LdapInvalidDnException
    {
        if ( schemaManager != null )
        {
            this.schemaManager = schemaManager;

            AttributeType tmpAttributeType = null;

            try
            {
                tmpAttributeType = schemaManager.lookupAttributeTypeRegistry( normType );
            }
            catch ( LdapException le )
            {
                if ( schemaManager.isRelaxed() )
                {
                    // No attribute in the schema, but the schema is relaxed : get out
                    return;
                }
                else
                {
                    String message = I18n.err( I18n.ERR_04188 );
                    LOG.error( message );
                    throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message, le );
                }
            }

            if ( this.attributeType == tmpAttributeType )
            {
                // No need to normalize again
                return;
            }
            else
            {
                this.attributeType = tmpAttributeType;
            }

            normType = tmpAttributeType.getOid();

            try
            {
                this.value.apply( tmpAttributeType );
            }
            catch ( LdapException le )
            {
                String message = I18n.err( I18n.ERR_04188 );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message, le );
            }

            hashCode();
        }
    }


    /**
     * Get the normalized type of a Ava
     *
     * @return The normalized type
     */
    public String getNormType()
    {
        return normType;
    }


    /**
     * Get the user provided type of a Ava
     *
     * @return The user provided type
     */
    public String getType()
    {
        return upType;
    }


    /**
     * Get the Value of a Ava
     *
     * @return The value
     */
    public Value<?> getValue()
    {
        return value.clone();
    }


    /**
     * Get the normalized Name of a Ava
     *
     * @return The name
     */
    public String getNormName()
    {
        return normalize();
    }


    /**
     * Get the user provided form of this attribute type and value
     *
     * @return The user provided form of this ava
     */
    public String getName()
    {
        return upName;
    }


    /**
     * Implements the cloning.
     *
     * @return a clone of this object
     */
    @Override
    public Ava clone()
    {
        try
        {
            Ava clone = ( Ava ) super.clone();
            clone.value = value.clone();

            return clone;
        }
        catch ( CloneNotSupportedException cnse )
        {
            throw new Error( "Assertion failure", cnse );
        }
    }


    /**
     * A Normalized String representation of a Ava :
     * <ul>
     * <li>type is trimed and lowercased</li>
     * <li>value is trimed and lowercased, and special characters are escaped if needed.</li>
     * </ul>
     *
     * @return A normalized string representing an Ava
     */
    public String normalize()
    {
        if ( value.isHumanReadable() )
        {
            // The result will be gathered in a stringBuilder
            StringBuilder sb = new StringBuilder();

            // First, store the type and the '=' char
            sb.append( normType ).append( '=' );

            String normalizedValue = ( String ) value.getNormValue();

            if ( ( normalizedValue != null ) && ( normalizedValue.length() > 0 ) )
            {
                sb.append( Rdn.escapeValue( normalizedValue ) );
            }

            return sb.toString();
        }
        else
        {
            return normType + "=#"
                + Strings.dumpHexPairs( value.getBytes() );
        }
    }


    /**
     * Gets the hashcode of this object.
     *
     * @see java.lang.Object#hashCode()
     * @return The instance hash code
     */
    @Override
    public int hashCode()
    {
        if ( h == 0 )
        {
            h = 37;

            h = h * 17 + ( normType != null ? normType.hashCode() : 0 );
            h = h * 17 + ( value != null ? value.hashCode() : 0 );
        }

        return h;
    }


    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals( Object obj )
    {
        if ( this == obj )
        {
            return true;
        }

        if ( !( obj instanceof Ava ) )
        {
            return false;
        }

        Ava instance = ( Ava ) obj;

        // Compare the type
        if ( normType == null )
        {
            if ( instance.normType != null )
            {
                return false;
            }
        }
        else
        {
            if ( !normType.equals( instance.normType ) )
            {
                return false;
            }
        }

        // Compare the values
        if ( value.isNull() )
        {
            return instance.value.isNull();
        }
        else
        {
            if ( schemaManager != null )
            {
                MatchingRule equalityMatchingRule = attributeType.getEquality();

                if ( equalityMatchingRule != null )
                {
                    return equalityMatchingRule.getLdapComparator().compare( value.getValue(),
                        instance.value.getValue() ) == 0;
                }
                else
                {
                    // No Equality MR, use a direct comparison
                    if ( value instanceof BinaryValue )
                    {
                        return Arrays.equals( value.getBytes(), instance.value.getBytes() );
                    }
                    else
                    {
                        return value.getString().equals( instance.value.getString() );
                    }
                }
            }
            else
            {
                return value.equals( instance.value );
            }
        }
    }


    /**
     * Serialize the AVA into a buffer at the given position.
     * 
     * @param buffer The buffer which will contain the serialized Ava
     * @param pos The position in the buffer for the serialized value
     * @return The new position in the buffer
     * @throws IOException If teh serialization failed
     */
    public int serialize( byte[] buffer, int pos ) throws IOException
    {
        if ( Strings.isEmpty( upName )
            || Strings.isEmpty( upType )
            || Strings.isEmpty( normType )
            || ( value.isNull() ) )
        {
            String message = "Cannot serialize an wrong ATAV, ";

            if ( Strings.isEmpty( upName ) )
            {
                message += "the upName should not be null or empty";
            }
            else if ( Strings.isEmpty( upType ) )
            {
                message += "the upType should not be null or empty";
            }
            else if ( Strings.isEmpty( normType ) )
            {
                message += "the normType should not be null or empty";
            }
            else if ( value.isNull() )
            {
                message += "the value should not be null";
            }

            LOG.error( message );
            throw new IOException( message );
        }

        int length = 0;

        // The upName
        byte[] upNameBytes = null;

        if ( upName != null )
        {
            upNameBytes = Strings.getBytesUtf8( upName );
            length += 1 + 4 + upNameBytes.length;
        }

        // The upType
        byte[] upTypeBytes = null;

        if ( upType != null )
        {
            upTypeBytes = Strings.getBytesUtf8( upType );
            length += 1 + 4 + upTypeBytes.length;
        }

        // The normType
        byte[] normTypeBytes = null;

        if ( normType != null )
        {
            normTypeBytes = Strings.getBytesUtf8( normType );
            length += 1 + 4 + normTypeBytes.length;
        }

        // Is HR
        length++;

        // The hash code
        length += 4;

        // Check that we will be able to store the data in the buffer
        if ( buffer.length - pos < length )
        {
            throw new ArrayIndexOutOfBoundsException();
        }

        // Write the upName
        if ( upName != null )
        {
            buffer[pos++] = Serialize.TRUE;
            pos = Serialize.serialize( upNameBytes, buffer, pos );
        }
        else
        {
            buffer[pos++] = Serialize.FALSE;
        }

        // Write the upType
        if ( upType != null )
        {
            buffer[pos++] = Serialize.TRUE;
            pos = Serialize.serialize( upTypeBytes, buffer, pos );
        }
        else
        {
            buffer[pos++] = Serialize.FALSE;
        }

        // Write the normType
        if ( normType != null )
        {
            buffer[pos++] = Serialize.TRUE;
            pos = Serialize.serialize( normTypeBytes, buffer, pos );
        }
        else
        {
            buffer[pos++] = Serialize.FALSE;
        }

        // Write the isHR flag
        if ( value.isHumanReadable() )
        {
            buffer[pos++] = Serialize.TRUE;
        }
        else
        {
            buffer[pos++] = Serialize.FALSE;
        }

        // Write the upValue
        if ( value.isHumanReadable() )
        {
            pos = ( ( StringValue ) value ).serialize( buffer, pos );
        }

        // Write the hash code
        pos = Serialize.serialize( h, buffer, pos );

        return pos;
    }


    /**
     * Deserialize an AVA from a byte[], starting at a given position
     * 
     * @param buffer The buffer containing the AVA
     * @param pos The position in the buffer
     * @return The new position
     * @throws IOException If the serialized value is not an AVA
     * @throws LdapInvalidAttributeValueException If the serialized AVA is invalid
     */
    public int deserialize( byte[] buffer, int pos ) throws IOException, LdapInvalidAttributeValueException
    {
        if ( ( pos < 0 ) || ( pos >= buffer.length ) )
        {
            throw new ArrayIndexOutOfBoundsException();
        }

        // Read the upName value, if it's not null
        boolean hasUpName = Serialize.deserializeBoolean( buffer, pos );
        pos++;

        if ( hasUpName )
        {
            byte[] wrappedValueBytes = Serialize.deserializeBytes( buffer, pos );
            pos += 4 + wrappedValueBytes.length;
            upName = Strings.utf8ToString( wrappedValueBytes );
        }

        // Read the upType value, if it's not null
        boolean hasUpType = Serialize.deserializeBoolean( buffer, pos );
        pos++;

        if ( hasUpType )
        {
            byte[] upTypeBytes = Serialize.deserializeBytes( buffer, pos );
            pos += 4 + upTypeBytes.length;
            upType = Strings.utf8ToString( upTypeBytes );
        }

        // Read the normType value, if it's not null
        boolean hasNormType = Serialize.deserializeBoolean( buffer, pos );
        pos++;

        if ( hasNormType )
        {
            byte[] normTypeBytes = Serialize.deserializeBytes( buffer, pos );
            pos += 4 + normTypeBytes.length;
            normType = Strings.utf8ToString( normTypeBytes );
        }

        // Update the AtributeType
        if ( schemaManager != null )
        {
            if ( !Strings.isEmpty( upType ) )
            {
                attributeType = schemaManager.getAttributeType( upType );
            }
            else
            {
                attributeType = schemaManager.getAttributeType( normType );
            }
        }

        // Read the isHR flag
        boolean isHR = Serialize.deserializeBoolean( buffer, pos );
        pos++;

        if ( isHR )
        {
            // Read the upValue
            value = new StringValue( attributeType );
            pos = ( ( StringValue ) value ).deserialize( buffer, pos );
        }

        // Read the hashCode
        h = Serialize.deserializeInt( buffer, pos );
        pos += 4;

        return pos;
    }


    /**
     * 
     * An Ava is composed of  a type and a value.
     * The data are stored following the structure :
     * <ul>
     *   <li>
     *     <b>upName</b> The User provided ATAV
     *   </li>
     *   <li>
     *     <b>start</b> The position of this ATAV in the Dn
     *   </li>
     *   <li>
     *     <b>length</b> The ATAV length
     *   </li>
     *   <li>
     *     <b>upType</b> The user Provided Type
     *   </li>
     *   <li>
     *     <b>normType</b> The normalized AttributeType
     *   </li>
     *   <li>
     *     <b>isHR</b> Tells if the value is a String or not
     *   </li>
     * </ul>
     * <br>
     * if the value is a String :
     * <ul>
     *   <li>
     *     <b>value</b> The value
     *   </li>
     * </ul>
     * <br>
     * if the value is binary :
     * <ul>
     *   <li>
     *     <b>valueLength</b>
     *   </li>
     *   <li>
     *     <b>value</b> The value
     *   </li>
     * </ul>
     * 
     * @see Externalizable#readExternal(ObjectInput)
     * 
     * @throws IOException If the Ava can't be written in the stream
     */
    @Override
    public void writeExternal( ObjectOutput out ) throws IOException
    {
        if ( Strings.isEmpty( upName )
            || Strings.isEmpty( upType )
            || Strings.isEmpty( normType )
            || ( value.isNull() ) )
        {
            String message = "Cannot serialize a wrong ATAV, ";

            if ( Strings.isEmpty( upName ) )
            {
                message += "the upName should not be null or empty";
            }
            else if ( Strings.isEmpty( upType ) )
            {
                message += "the upType should not be null or empty";
            }
            else if ( Strings.isEmpty( normType ) )
            {
                message += "the normType should not be null or empty";
            }
            else if ( value.isNull() )
            {
                message += "the value should not be null";
            }

            LOG.error( message );
            throw new IOException( message );
        }

        if ( upName != null )
        {
            out.writeBoolean( true );
            out.writeUTF( upName );
        }
        else
        {
            out.writeBoolean( false );
        }

        if ( upType != null )
        {
            out.writeBoolean( true );
            out.writeUTF( upType );
        }
        else
        {
            out.writeBoolean( false );
        }

        if ( normType != null )
        {
            out.writeBoolean( true );
            out.writeUTF( normType );
        }
        else
        {
            out.writeBoolean( false );
        }

        boolean isHR = value.isHumanReadable();

        out.writeBoolean( isHR );

        value.writeExternal( out );

        // Write the hashCode
        out.writeInt( h );

        out.flush();
    }


    /**
     * We read back the data to create a new ATAV. The structure
     * read is exposed in the {@link Ava#writeExternal(ObjectOutput)}
     * method
     * 
     * @see Externalizable#readExternal(ObjectInput)
     * 
     * @throws IOException If the Ava can't b written to the stream
     * @throws ClassNotFoundException If we can't deserialize an Ava from the stream
     */
    @Override
    public void readExternal( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        boolean hasUpName = in.readBoolean();

        if ( hasUpName )
        {
            upName = in.readUTF();
        }

        boolean hasUpType = in.readBoolean();

        if ( hasUpType )
        {
            upType = in.readUTF();
        }

        boolean hasNormType = in.readBoolean();

        if ( hasNormType )
        {
            normType = in.readUTF();
        }

        if ( schemaManager != null )
        {
            if ( !Strings.isEmpty( upType ) )
            {
                attributeType = schemaManager.getAttributeType( upType );
            }
            else
            {
                attributeType = schemaManager.getAttributeType( normType );
            }
        }

        boolean isHR = in.readBoolean();

        if ( isHR )
        {
            value = StringValue.deserialize( attributeType, in );
        }
        else
        {
            value = BinaryValue.deserialize( attributeType, in );
        }

        h = in.readInt();

        if ( schemaManager != null )
        {
            attributeType = schemaManager.getAttributeType( upType );
        }
    }


    /**
     * Tells if the Ava is schema aware or not.
     * 
     * @return true if the Ava is schema aware
     */
    public boolean isSchemaAware()
    {
        return attributeType != null;
    }


    /**
     * @return the attributeType
     */
    public AttributeType getAttributeType()
    {
        return attributeType;
    }


    private int compareValues( Ava that )
    {
        int comp;

        if ( value.getNormValue() instanceof String )
        {
            comp = ( ( String ) value.getNormValue() ).compareTo( ( String ) that.value.getNormValue() );

            return comp;
        }
        else
        {
            byte[] bytes1 = ( byte[] ) value.getNormValue();
            byte[] bytes2 = ( byte[] ) that.value.getNormValue();

            for ( int pos = 0; pos < bytes1.length; pos++ )
            {
                int v1 = bytes1[pos] & 0x00FF;
                int v2 = bytes2[pos] & 0x00FF;

                if ( v1 > v2 )
                {
                    return 1;
                }
                else if ( v2 > v1 )
                {
                    return -1;
                }
            }

            return 0;
        }

    }


    /**
     * @see Comparable#compareTo(Object)
     */
    @Override
    public int compareTo( Ava that )
    {
        if ( that == null )
        {
            return 1;
        }

        int comp;

        if ( schemaManager == null )
        {
            // Compare the ATs
            comp = normType.compareTo( that.normType );

            if ( comp != 0 )
            {
                return comp;
            }

            // and compare the values
            if ( value == null )
            {
                if ( that.value == null )
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
                if ( that.value == null )
                {
                    return 1;
                }
                else
                {
                    if ( value instanceof StringValue )
                    {
                        comp = ( ( StringValue ) value ).compareTo( ( StringValue ) that.value );

                        return comp;
                    }
                    else
                    {
                        comp = ( ( BinaryValue ) value ).compareTo( ( BinaryValue ) that.value );

                        return comp;
                    }
                }
            }
        }
        else
        {
            if ( that.schemaManager == null )
            {
                // Problem : we will apply the current Ava SchemaManager to the given Ava
                try
                {
                    that.apply( schemaManager );
                }
                catch ( LdapInvalidDnException lide )
                {
                    return 1;
                }
            }

            // First compare the AT OID
            comp = attributeType.getOid().compareTo( that.attributeType.getOid() );

            if ( comp != 0 )
            {
                return comp;
            }

            // Now, compare the two values using the ordering matchingRule comparator, if any
            MatchingRule orderingMR = attributeType.getOrdering();

            if ( orderingMR != null )
            {
                LdapComparator<Object> comparator = ( LdapComparator<Object> ) orderingMR.getLdapComparator();

                if ( comparator != null )
                {
                    comp = comparator.compare( value.getNormValue(), that.value.getNormValue() );

                    return comp;
                }
                else
                {
                    comp = compareValues( that );

                    return comp;
                }
            }
            else
            {
                comp = compareValues( that );

                return comp;
            }
        }
    }
    
    
    /**
     * A String representation of an Ava, as provided by the user.
     *
     * @return A string representing an Ava
     */
    @Override
    public String toString()
    {
        return upName;
    }
}
