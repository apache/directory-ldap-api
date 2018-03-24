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
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Serialize;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * <p>
 * A Attribute Type And Value, which is the basis of all Rdn. It contains a
 * type, and a value. The type must not be case sensitive. Superfluous leading
 * and trailing spaces MUST have been trimmed before. The value MUST be in UTF8
 * format, according to RFC 2253. If the type is in OID form, then the value
 * must be a hexadecimal string prefixed by a '#' character. Otherwise, the
 * string must respect the RC 2253 grammar.
 * </p>
 * <p>
 * We will also keep a User Provided form of the AVA (Attribute Type And Value),
 * called upName.
 * </p>
 * <p>
 * This class is immutable
 * </p>
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
    private Value value;

    /** The user provided Ava */
    private String upName;

    /** The attributeType if the Ava is schemaAware */
    private AttributeType attributeType;

    /** the schema manager */
    private transient SchemaManager schemaManager;

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
        attributeType = null;
    }


    /**
     * Constructs new Ava using the provided SchemaManager and AVA
     * 
     * @param schemaManager The SchemaManager instance
     * @param ava The AVA to copy
     * @throws LdapInvalidDnException If the Ava is invalid
     */
    public Ava( SchemaManager schemaManager, Ava ava ) throws LdapInvalidDnException
    {
        upType = ava.upType;
        
        if ( ava.isSchemaAware() )
        {
            normType = ava.normType;
            value = ava.value;
            attributeType = ava.getAttributeType();
        }
        else
        {
            if ( schemaManager != null )
            {
                attributeType = schemaManager.getAttributeType( ava.normType );
                
                if ( attributeType != null )
                {
                    normType = attributeType.getOid();

                    try
                    {
                        value = new Value( attributeType, ava.value );
                    }
                    catch ( LdapInvalidAttributeValueException e )
                    {
                        throw new LdapInvalidDnException( e.getResultCode() );
                    }
                }
                else
                {
                    normType = ava.normType;
                    value = ava.value;
                }
            }
            else
            {
                normType = ava.normType;
                value = ava.value;
            }
        }
        
        StringBuilder sb = new StringBuilder( upType );
        sb.append( '=' );
        
        if ( ( value != null ) && ( value.getValue() != null ) )
        {
            sb.append( value.getValue() );
        }
        
        upName = sb.toString();

        hashCode();
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
                String message = I18n.err( I18n.ERR_13600_TYPE_IS_NULL_OR_EMPTY );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message, le );
            }

            try
            {
                createAva( schemaManager, upType, new Value( attributeType, upValue ) );
            }
            catch ( LdapInvalidAttributeValueException liave )
            {
                String message = I18n.err( I18n.ERR_13600_TYPE_IS_NULL_OR_EMPTY );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message, liave );
            }
        }
        else
        {
            createAva( upType, new Value( upValue ) );
        }
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
     * @param upName the User Provided AVA
     * @param upValue The User Provided binary value
     * 
     * @throws LdapInvalidDnException If the given type or value are invalid
     */
    public Ava( SchemaManager schemaManager, String upType, String upName, byte[] upValue ) throws LdapInvalidDnException
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
                String message = I18n.err( I18n.ERR_13600_TYPE_IS_NULL_OR_EMPTY );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message, le );
            }

            try
            {
                createAva( schemaManager, upType, new Value( attributeType, upValue ) );
            }
            catch ( LdapInvalidAttributeValueException liave )
            {
                String message = I18n.err( I18n.ERR_13600_TYPE_IS_NULL_OR_EMPTY );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message, liave );
            }
        }
        else
        {
            createAva( upType, new Value( upValue ) );
        }
        
        this.upName = upName;
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
                String message = I18n.err( I18n.ERR_13600_TYPE_IS_NULL_OR_EMPTY );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message, le );
            }

            try
            {
                createAva( schemaManager, upType, new Value( attributeType, upValue ) );
            }
            catch ( LdapInvalidAttributeValueException liave )
            {
                String message = I18n.err( I18n.ERR_13600_TYPE_IS_NULL_OR_EMPTY );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message, liave );
            }
        }
        else
        {
            createAva( upType, new Value( upValue ) );
        }
    }


    /**
     * Construct a schema aware Ava with a String value.
     * <p>
     * Note that the upValue should <b>not</b> be null or empty, or resolve
     * to an empty string after having trimmed it.
     *
     * @param schemaManager The SchemaManager instance
     * @param upType The User Provided type
     * @param upName the User provided AVA
     * @param upValue The User Provided String value
     * 
     * @throws LdapInvalidDnException If the given type or value are invalid
     */
    public Ava( SchemaManager schemaManager, String upType, String upName, String upValue ) throws LdapInvalidDnException
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
                String message = I18n.err( I18n.ERR_13600_TYPE_IS_NULL_OR_EMPTY );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message, le );
            }

            try
            {
                createAva( schemaManager, upType, new Value( attributeType, upValue ) );
            }
            catch ( LdapInvalidAttributeValueException liave )
            {
                String message = I18n.err( I18n.ERR_13600_TYPE_IS_NULL_OR_EMPTY );
                LOG.error( message );
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, message, liave );
            }
        }
        else
        {
            createAva( upType, new Value( upValue ) );
        }
        
        this.upName = upName;
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
    /* Unspecified protection */Ava( String upType, String normType, Value value, String upName )
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
    /* Unspecified protection */Ava( AttributeType attributeType, String upType, String normType, Value value, String upName )
        throws LdapInvalidDnException
    {
        this.attributeType = attributeType;
        String upTypeTrimmed = Strings.trim( upType );
        String normTypeTrimmed = Strings.trim( normType );

        if ( Strings.isEmpty( upTypeTrimmed ) )
        {
            if ( Strings.isEmpty( normTypeTrimmed ) )
            {
                String message = I18n.err( I18n.ERR_13600_TYPE_IS_NULL_OR_EMPTY );
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
    /* Unspecified protection */Ava( SchemaManager schemaManager, String upType, String normType, Value value )
        throws LdapInvalidDnException
    {
        StringBuilder sb = new StringBuilder();

        this.upType = upType;
        this.normType = normType;
        this.value = value;
        
        sb.append( upType );
        sb.append( '=' );
        
        if ( ( value != null ) && ( value.getValue() != null ) )
        {
            sb.append( value.getValue() );
        }
        
        upName = sb.toString();

        if ( schemaManager != null )
        {
            apply( schemaManager );
        }

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
    private void createAva( SchemaManager schemaManager, String upType, Value value )
        throws LdapInvalidDnException
    {
        StringBuilder sb = new StringBuilder();

        normType = attributeType.getOid();
        this.upType = upType;
        this.value = value;
        
        sb.append( upType );
        sb.append( '=' );
        
        if ( value != null )
        {
            sb.append( Rdn.escapeValue( value.getValue() ) );
        }
        
        upName = sb.toString();

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
    private void createAva( String upType, Value upValue ) throws LdapInvalidDnException
    {
        String upTypeTrimmed = Strings.trim( upType );
        String normTypeTrimmed = Strings.trim( normType );

        if ( Strings.isEmpty( upTypeTrimmed ) )
        {
            if ( Strings.isEmpty( normTypeTrimmed ) )
            {
                String message = I18n.err( I18n.ERR_13600_TYPE_IS_NULL_OR_EMPTY );
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

        upName = getEscaped();
        
        hashCode();
    }


    /**
     * Apply a SchemaManager to the Ava. It will normalize the Ava.<br/>
     * If the Ava already had a SchemaManager, then the new SchemaManager will be
     * used instead.
     * 
     * @param schemaManager The SchemaManager instance to use
     * @throws LdapInvalidDnException If the Ava can't be normalized accordingly
     * to the given SchemaManager
     */
    private void apply( SchemaManager schemaManager ) throws LdapInvalidDnException
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
                    String message = I18n.err( I18n.ERR_13600_TYPE_IS_NULL_OR_EMPTY );
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

            try
            {
                value = new Value( tmpAttributeType, value );
            }
            catch ( LdapException le )
            {
                String message = I18n.err( I18n.ERR_13600_TYPE_IS_NULL_OR_EMPTY );
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
    public Value getValue()
    {
        return value.clone();
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
     * @return The Ava as an escaped String
     */
    public String getEscaped()
    {
        StringBuilder sb = new StringBuilder();
        
        sb.append( getType() );
        sb.append( '=' );
        
        if ( value == null )
        {
            return sb.toString();
        }
        
        byte[] bytes = value.getBytes();
        
        if ( Strings.isEmpty( bytes ) )
        {
            return sb.toString();
        }
        
        boolean leadChar = true;
        
        for ( int pos = 0; pos < bytes.length; pos++  )
        {
            boolean trailChar = pos == bytes.length - 1;
            byte b = bytes[pos];

            switch ( b )
            {
                case 0x00 :
                    sb.append( "\\00" );
                    break;

                case 0x01 :
                case 0x02 :
                case 0x03 :
                case 0x04 :
                case 0x05 :
                case 0x06 :
                case 0x07 :
                case 0x08 :
                case 0x09 :
                case 0x0A :
                case 0x0B :
                case 0x0C :
                case 0x0D :
                case 0x0E :
                case 0x0F :
                case 0x10 :
                case 0x11 :
                case 0x12 :
                case 0x13 :
                case 0x14 :
                case 0x15 :
                case 0x16 :
                case 0x17 :
                case 0x18 :
                case 0x19 :
                case 0x1A :
                case 0x1B :
                case 0x1C :
                case 0x1D :
                case 0x1E :
                case 0x1F :
                    sb.append( ( char ) b );
                    break;
                    
                case 0x20 :
                    if ( leadChar || trailChar )
                    {
                        sb.append( "\\ " );
                    }
                    else
                    {
                        sb.append( ( char ) b );
                    }
                    
                    break;
                    
                case 0x21 :
                    sb.append( ( char ) b );
                    break;
                    
                    
                case 0x22 :
                    sb.append( "\\\"" );
                    break;

                case 0x23 :
                    if ( leadChar )
                    {
                        sb.append( "\\#" );
                    }
                    else
                    {
                        sb.append( '#' );
                    }
                    
                    break;

                case 0x24 :
                case 0x25 :
                case 0x26 :
                case 0x27 :
                case 0x28 :
                case 0x29 :
                case 0x2A :
                    sb.append( ( char ) b );
                    break;
                    
                case 0x2B :
                    sb.append( "\\+" );
                    break;

                case 0x2C :
                    sb.append( "\\," );
                    break;

                case 0x2D :
                case 0x2E :
                case 0x2F :
                case 0x30 :
                case 0x31 :
                case 0x32 :
                case 0x33 :
                case 0x34 :
                case 0x35 :
                case 0x36 :
                case 0x37 :
                case 0x38 :
                case 0x39 :
                case 0x3A :
                    sb.append( ( char ) b );
                    break;
                    
                case 0x3B :
                    sb.append( "\\;" );
                    break;

                case 0x3C :
                    sb.append( "\\<" );
                    break;

                case 0x3D :
                    sb.append( ( char ) b );
                    break;
                    
                case 0x3E :
                    sb.append( "\\>" );
                    break;
                
                case 0x3F :
                case 0x40 :
                case 0x41 :
                case 0x42 :
                case 0x43 :
                case 0x44 :
                case 0x45 :
                case 0x46 :
                case 0x47 :
                case 0x48 :
                case 0x49 :
                case 0x4A :
                case 0x4B :
                case 0x4C :
                case 0x4D :
                case 0x4E :
                case 0x4F :
                case 0x50 :
                case 0x51 :
                case 0x52 :
                case 0x53 :
                case 0x54 :
                case 0x55 :
                case 0x56 :
                case 0x57 :
                case 0x58 :
                case 0x59 :
                case 0x5A :
                case 0x5B :
                    sb.append( ( char ) b );
                    break;
                    
                case 0x5C :
                    sb.append( "\\\\" );
                    break;

                case 0x5D :
                case 0x5E :
                case 0x5F :
                case 0x60 :
                case 0x61 :
                case 0x62 :
                case 0x63 :
                case 0x64 :
                case 0x65 :
                case 0x66 :
                case 0x67 :
                case 0x68 :
                case 0x69 :
                case 0x6A :
                case 0x6B :
                case 0x6C :
                case 0x6D :
                case 0x6E :
                case 0x6F :
                case 0x70 :
                case 0x71 :
                case 0x72 :
                case 0x73 :
                case 0x74 :
                case 0x75 :
                case 0x76 :
                case 0x77 :
                case 0x78 :
                case 0x79 :
                case 0x7A :
                case 0x7B :
                case 0x7C :
                case 0x7D :
                case 0x7E :
                case 0x7F :
                    sb.append( ( char ) b );
                    break;

                // Between 0x80 and 0xC1, this is an octet
                case ( byte ) 0x80 :
                case ( byte ) 0x81 :
                case ( byte ) 0x82 :
                case ( byte ) 0x83 :
                case ( byte ) 0x84 :
                case ( byte ) 0x85 :
                case ( byte ) 0x86 :
                case ( byte ) 0x87 :
                case ( byte ) 0x88 :
                case ( byte ) 0x89 :
                case ( byte ) 0x8A :
                case ( byte ) 0x8B :
                case ( byte ) 0x8C :
                case ( byte ) 0x8D :
                case ( byte ) 0x8E :
                case ( byte ) 0x8F :
                case ( byte ) 0x90 :
                case ( byte ) 0x91 :
                case ( byte ) 0x92 :
                case ( byte ) 0x93 :
                case ( byte ) 0x94 :
                case ( byte ) 0x95 :
                case ( byte ) 0x96 :
                case ( byte ) 0x97 :
                case ( byte ) 0x98 :
                case ( byte ) 0x99 :
                case ( byte ) 0x9A :
                case ( byte ) 0x9B :
                case ( byte ) 0x9C :
                case ( byte ) 0x9D :
                case ( byte ) 0x9E :
                case ( byte ) 0x9F :
                case ( byte ) 0xA0 :
                case ( byte ) 0xA1 :
                case ( byte ) 0xA2 :
                case ( byte ) 0xA3 :
                case ( byte ) 0xA4 :
                case ( byte ) 0xA5 :
                case ( byte ) 0xA6 :
                case ( byte ) 0xA7 :
                case ( byte ) 0xA8 :
                case ( byte ) 0xA9 :
                case ( byte ) 0xAA :
                case ( byte ) 0xAB :
                case ( byte ) 0xAC :
                case ( byte ) 0xAD :
                case ( byte ) 0xAE :
                case ( byte ) 0xAF :
                case ( byte ) 0xB0 :
                case ( byte ) 0xB1 :
                case ( byte ) 0xB2 :
                case ( byte ) 0xB3 :
                case ( byte ) 0xB4 :
                case ( byte ) 0xB5 :
                case ( byte ) 0xB6 :
                case ( byte ) 0xB7 :
                case ( byte ) 0xB8 :
                case ( byte ) 0xB9 :
                case ( byte ) 0xBA :
                case ( byte ) 0xBB :
                case ( byte ) 0xBC :
                case ( byte ) 0xBD :
                case ( byte ) 0xBE :
                case ( byte ) 0xBF :
                case ( byte ) 0xC0 :
                case ( byte ) 0xC1 :
                    sb.append( '\\' ).append( Strings.byteToString( b ) );
                    break;

                // Between 0xC2 and 0xDF, we may have a UTF-2 char
                case ( byte ) 0xC2 :
                case ( byte ) 0xC3 :
                case ( byte ) 0xC4 :
                case ( byte ) 0xC5 :
                case ( byte ) 0xC6 :
                case ( byte ) 0xC7 :
                case ( byte ) 0xC8 :
                case ( byte ) 0xC9 :
                case ( byte ) 0xCA :
                case ( byte ) 0xCB :
                case ( byte ) 0xCC :
                case ( byte ) 0xCD :
                case ( byte ) 0xCE :
                case ( byte ) 0xCF :
                case ( byte ) 0xD0 :
                case ( byte ) 0xD1 :
                case ( byte ) 0xD2 :
                case ( byte ) 0xD3 :
                case ( byte ) 0xD4 :
                case ( byte ) 0xD5 :
                case ( byte ) 0xD6 :
                case ( byte ) 0xD7 :
                case ( byte ) 0xD8 :
                case ( byte ) 0xD9 :
                case ( byte ) 0xDA :
                case ( byte ) 0xDB :
                case ( byte ) 0xDC :
                case ( byte ) 0xDD :
                case ( byte ) 0xDE :
                case ( byte ) 0xDF :
                    // UTF2, if the following byte is in [0x80-0xBF]
                    if ( trailChar )
                    {
                        // No next byte : this is an octet
                        sb.append( '\\' ).append( Strings.byteToString( b ) );
                    }
                    else
                    {
                        int b2 = bytes[pos + 1] & 0x00FF;
                        
                        if ( ( b2 >= 0x0080 ) && ( b2 <= 0x00BF ) )
                        {
                            // This is an UTF-2 char
                            sb.append( Strings.utf8ToString( bytes, pos, 2 ) );
                            pos++;
                        }
                        else
                        {
                            // Not an UTF-2
                            sb.append( '\\' ).append( Strings.byteToString( b ) );
                        }
                    }
                
                    break;

                case ( byte ) 0xE0 :
                    // May be an UTF-3, if the next byte is in [0xA0-0xBF], followed by a byte in [0x80-0xBF]
                    if ( trailChar )
                    {
                        // No next byte : this is an octet
                        sb.append( '\\' ).append( Strings.byteToString( b ) );
                        break;
                    }
                    
                    if ( pos == bytes.length - 2 )
                    {
                        // We only have 2 bytes : not an UTF-3
                        sb.append( '\\' ).append( Strings.byteToString( b ) );
                    }
                    else
                    {
                        int b2 = bytes[pos + 1] & 0x00FF;
                        
                        if ( ( b2 >= 0x00A0 ) && ( b2 <= 0x00BF ) )
                        {
                            int b3 = bytes[pos + 2] & 0x00FF;
                            
                            // Check that the third byte is in between 0x80-0xBF
                            if ( ( b3 >= 0x0080 ) && ( b3 <= 0x00BF ) )
                            {
                                // UTF-3
                                sb.append( Strings.utf8ToString( bytes, pos, 3 ) );
                                pos += 2;
                            }
                            else
                            {
                                // Not an UTF-3, dump one bytes
                                sb.append( '\\' ).append( Strings.byteToString( b ) );
                            }
                        }
                        else
                        {
                            // Not an UTF-3 : dump two byte
                            sb.append( '\\' ).append( Strings.byteToString( b ) );
                        }
                    }
                    
                    break;
                    

                // Between E1 and EC, this may be an UTF-3 if the next two bytes are between 0x80 and 0xBF
                case ( byte ) 0xE1 :
                case ( byte ) 0xE2 :
                case ( byte ) 0xE3 :
                case ( byte ) 0xE4 :
                case ( byte ) 0xE5 :
                case ( byte ) 0xE6 :
                case ( byte ) 0xE7 :
                case ( byte ) 0xE8 :
                case ( byte ) 0xE9 :
                case ( byte ) 0xEA :
                case ( byte ) 0xEB :
                case ( byte ) 0xEC :
                case ( byte ) 0xEE :
                case ( byte ) 0xEF :
                    if ( trailChar )
                    {
                        // No next byte : this is an octet
                        sb.append( '\\' ).append( Strings.byteToString( b ) );
                        break;
                    }
                    
                    if ( pos == bytes.length - 2 )
                    {
                        // We only have 2 bytes : not an UTF-3
                        sb.append( '\\' ).append( Strings.byteToString( b ) );
                    }
                    else
                    {
                        int b2 = bytes[pos + 1] & 0x00FF;
                        
                        if ( ( b2 >= 0x0080 ) && ( b2 <= 0x00BF ) )
                        {
                            int b3 = bytes[pos + 2] & 0x00FF;
                            
                            // Check that the third byte is in between 0x80-0xBF
                            if ( ( b3 >= 0x0080 ) && ( b3 <= 0x00BF ) )
                            {
                                // UTF-3
                                sb.append( Strings.utf8ToString( bytes, pos, 3 ) );
                                pos += 2;
                            }
                            else
                            {
                                // Not an UTF-3, dump one byte
                                sb.append( '\\' ).append( Strings.byteToString( b ) );
                            }
                        }
                        else
                        {
                            // Not an UTF-3 : dump one byte
                            sb.append( '\\' ).append( Strings.byteToString( b ) );
                            pos++;
                        }
                    }
                    
                    break;

                case ( byte ) 0xED :
                    // May be an UTF-3 if the second byte is in [0x80-0x9F] and the third byte in [0x80-0xBF]
                    if ( trailChar )
                    {
                        // No next byte : this is an octet
                        sb.append( '\\' ).append( Strings.byteToString( b ) );
                        break;
                    }
                    
                    if ( pos == bytes.length - 2 )
                    {
                        // We only have 2 bytes : not an UTF-3
                        sb.append( '\\' ).append( Strings.byteToString( b ) );
                    }
                    else
                    {
                        int b2 = bytes[pos + 1] & 0x00FF;
                        
                        if ( ( b2 >= 0x0080 ) && ( b2 <= 0x009F ) )
                        {
                            int b3 = bytes[pos + 2] & 0x00FF;
                            
                            // Check that the third byte is in between 0x80-0xBF
                            if ( ( b3 >= 0x0080 ) && ( b3 <= 0x00BF ) )
                            {
                                // UTF-3
                                sb.append( Strings.utf8ToString( bytes, pos, 3 ) );
                                pos += 2;
                            }
                            else
                            {
                                // Not an UTF-3, dump one byte
                                sb.append( '\\' ).append( Strings.byteToString( b ) );
                            }
                        }
                        else
                        {
                            // Not an UTF-3 : dump one byte
                            sb.append( '\\' ).append( Strings.byteToString( b ) );
                            pos++;
                        }
                    }
                    
                    break;

                case ( byte ) 0xF0 :
                    // May be an UTF-4 if the second byte is in [0x90-0xBF] followed by two bytes in [0x80-0xBF]
                    if ( trailChar )
                    {
                        // No next byte : this is an octet
                        sb.append( '\\' ).append( Strings.byteToString( b ) );
                        break;
                    }
                    
                    if ( pos == bytes.length - 3 )
                    {
                        // We only have 2 bytes : not an UTF-4
                        sb.append( '\\' ).append( Strings.byteToString( b ) );
                    }
                    else
                    {
                        int b2 = bytes[pos + 1] & 0x00FF;
                        
                        if ( ( b2 >= 0x0090 ) && ( b2 <= 0x00BF ) )
                        {
                            int b3 = bytes[pos + 2] & 0x00FF;
                            
                            // Check that the third byte is in between 0x80-0xBF
                            if ( ( b3 >= 0x0080 ) && ( b3 <= 0x00BF ) )
                            {
                                int b4 = bytes[pos + 3] & 0x00FF;
                                
                                // Check that the forth byte is in between 0x80-0xBF
                                if ( ( b4 >= 0x0080 ) && ( b4 <= 0x00BF ) )
                                {
                                    // UTF-4
                                    sb.append( Strings.utf8ToString( bytes, pos, 4 ) );
                                    pos += 3;
                                }
                                else
                                {
                                    // Not an UTF-4, dump one byte
                                    sb.append( '\\' ).append( Strings.byteToString( b ) );
                                }
                            }
                            else
                            {
                                // Not an UTF-4, dump one byte
                                sb.append( '\\' ).append( Strings.byteToString( b ) );
                            }
                        }
                        else
                        {
                            // Not an UTF-4 : dump one byte
                            sb.append( '\\' ).append( Strings.byteToString( b ) );
                            pos++;
                        }
                    }
                    
                    break;

                case ( byte ) 0xF1 :
                case ( byte ) 0xF2 :
                case ( byte ) 0xF3 :
                    // May be an UTF-4
                    // May be an UTF-4 if it's followed by three bytes in [0x80-0xBF]
                    if ( trailChar )
                    {
                        // No next byte : this is an octet
                        sb.append( '\\' ).append( Strings.byteToString( b ) );
                        break;
                    }
                    
                    if ( pos == bytes.length - 3 )
                    {
                        // We only have 2 bytes : not an UTF-4
                        sb.append( '\\' ).append( Strings.byteToString( b ) );
                    }
                    else
                    {
                        int b2 = bytes[pos + 1] & 0x00FF;
                        
                        if ( ( b2 >= 0x0080 ) && ( b2 <= 0x00BF ) )
                        {
                            int b3 = bytes[pos + 2] & 0x00FF;
                            
                            // Check that the third byte is in between 0x80-0xBF
                            if ( ( b3 >= 0x0080 ) && ( b3 <= 0x00BF ) )
                            {
                                int b4 = bytes[pos + 3] & 0x00FF;
                                
                                // Check that the forth byte is in between 0x80-0xBF
                                if ( ( b4 >= 0x0080 ) && ( b4 <= 0x00BF ) )
                                {
                                    // UTF-4
                                    sb.append( Strings.utf8ToString( bytes, pos, 4 ) );
                                    pos += 3;
                                }
                                else
                                {
                                    // Not an UTF-4, dump one byte
                                    sb.append( '\\' ).append( Strings.byteToString( b ) );
                                }
                            }
                            else
                            {
                                // Not an UTF-4, dump one byte
                                sb.append( '\\' ).append( Strings.byteToString( b ) );
                            }
                        }
                        else
                        {
                            // Not an UTF-4 : dump one byte
                            sb.append( '\\' ).append( Strings.byteToString( b ) );
                            pos++;
                        }
                    }
                    
                    break;

                case ( byte ) 0xF4 :
                    // May be an UTF-4 if the second byte is in [0x80-0x8F] followed by two bytes in [0x80-0xBF]
                    if ( trailChar )
                    {
                        // No next byte : this is an octet
                        sb.append( '\\' ).append( Strings.byteToString( b ) );
                        break;
                    }
                    
                    if ( pos == bytes.length - 3 )
                    {
                        // We only have 2 bytes : not an UTF-4
                        sb.append( '\\' ).append( Strings.byteToString( b ) );
                    }
                    else
                    {
                        int b2 = bytes[pos + 1] & 0x00FF;
                        
                        if ( ( b2 >= 0x0080 ) && ( b2 <= 0x008F ) )
                        {
                            int b3 = bytes[pos + 2] & 0x00FF;
                            
                            // Check that the third byte is in between 0x80-0xBF
                            if ( ( b3 >= 0x0080 ) && ( b3 <= 0x00BF ) )
                            {
                                int b4 = bytes[pos + 3] & 0x00FF;
                                
                                // Check that the forth byte is in between 0x80-0xBF
                                if ( ( b4 >= 0x0080 ) && ( b4 <= 0x00BF ) )
                                {
                                    // UTF-4
                                    sb.append( Strings.utf8ToString( bytes, pos, 4 ) );
                                    pos += 3;
                                }
                                else
                                {
                                    // Not an UTF-4, dump one byte
                                    sb.append( '\\' ).append( Strings.byteToString( b ) );
                                }
                            }
                            else
                            {
                                // Not an UTF-4, dump one byte
                                sb.append( '\\' ).append( Strings.byteToString( b ) );
                            }
                        }
                        else
                        {
                            // Not an UTF-4 : dump one byte
                            sb.append( '\\' ).append( Strings.byteToString( b ) );
                            pos++;
                        }
                    }
                    
                    break;


                default :
                    // octet
                    sb.append( '\\' ).append( Strings.byteToString( b ) );

                    break;
                    
            }
            
            if ( leadChar )
            {
                leadChar = false;
            }
        }
        
        return sb.toString();
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
            throw new Error( I18n.err( I18n.ERR_13621_ASSERTION_FAILURE ), cnse );
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
        if ( attributeType == null )
        {
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
        }
        else
        {
            if ( instance.getAttributeType() == null )
            {
                if ( ( schemaManager != null ) 
                        && !attributeType.equals( schemaManager.getAttributeType( instance.getType() ) ) )
                {
                    return false;
                }
            }
            else if ( !attributeType.equals( instance.getAttributeType() ) )
            {
                return false;
            }
        }

        // Compare the values
        if ( ( value == null ) || value.isNull() )
        {
            return ( instance.value == null ) || instance.value.isNull();
        }
        else
        {
            if ( schemaManager != null )
            {
                if ( ( value.getValue() != null ) && value.getValue().equals( instance.value.getValue() ) )
                {
                    return true;
                }

                if ( attributeType == null )
                {
                    attributeType = schemaManager.getAttributeType( normType );
                }
                
                MatchingRule equalityMatchingRule = attributeType.getEquality();

                if ( equalityMatchingRule != null )
                {
                    Normalizer normalizer = equalityMatchingRule.getNormalizer();
                    
                    try
                    {
                        return equalityMatchingRule.getLdapComparator().compare( normalizer.normalize( value.getValue() ),
                            instance.value.getValue() ) == 0;
                    }
                    catch ( LdapException le )
                    {
                        LOG.error( I18n.err( I18n.ERR_13620_CANNOT_NORMALIZE_VALUE ), le.getMessage() );
                        return false;
                    }
                }
                else
                {
                    // No Equality MR, use a direct comparison
                    if ( !value.isHumanReadable() )
                    {
                        return Arrays.equals( value.getBytes(), instance.value.getBytes() );
                    }
                    else
                    {
                        return value.getValue().equals( instance.value.getValue() );
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
     * @throws IOException Id the serialization failed
     */
    public int serialize( byte[] buffer, int pos ) throws IOException
    {
        if ( Strings.isEmpty( upName )
            || Strings.isEmpty( upType )
            || Strings.isEmpty( normType )
            || ( value.isNull() ) )
        {
            String message;

            if ( Strings.isEmpty( upName ) )
            {
                message = I18n.err( I18n.ERR_13616_CANNOT_SERIALIZE_AVA_UPNAME_NULL );
            }
            else if ( Strings.isEmpty( upType ) )
            {
                message = I18n.err( I18n.ERR_13617_CANNOT_SERIALIZE_AVA_UPTYPE_NULL );
            }
            else if ( Strings.isEmpty( normType ) )
            {
                message = I18n.err( I18n.ERR_13618_CANNOT_SERIALIZE_AVA_NORMTYPE_NULL );
            }
            else
            {
                message = I18n.err( I18n.ERR_13619_CANNOT_SERIALIZE_AVA_VALUE_NULL );
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
            pos = value.serialize( buffer, pos );
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

        if ( attributeType != null )
        {
            normType = attributeType.getOid();
        }
        else
        {
            normType = upType;
        }

        // Read the isHR flag
        boolean isHR = Serialize.deserializeBoolean( buffer, pos );
        pos++;

        if ( isHR )
        {
            // Read the upValue
            value = Value.createValue( attributeType );
            pos = value.deserialize( buffer, pos );
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
            String message;

            if ( Strings.isEmpty( upName ) )
            {
                message = I18n.err( I18n.ERR_13616_CANNOT_SERIALIZE_AVA_UPNAME_NULL );
            }
            else if ( Strings.isEmpty( upType ) )
            {
                message = I18n.err( I18n.ERR_13617_CANNOT_SERIALIZE_AVA_UPTYPE_NULL );
            }
            else if ( Strings.isEmpty( normType ) )
            {
                message = I18n.err( I18n.ERR_13618_CANNOT_SERIALIZE_AVA_NORMTYPE_NULL );
            }
            else
            {
                message = I18n.err( I18n.ERR_13619_CANNOT_SERIALIZE_AVA_VALUE_NULL );
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

        in.readBoolean();

        value = Value.deserialize( attributeType, in );

        h = in.readInt();
    }


    /**
     * Tells if the Ava is schema aware or not.
     * 
     * @return <tt>true</tt> if the Ava is schema aware
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

        if ( value.isHumanReadable() )
        {
            comp = value.compareTo( that.value );

            return comp;
        }
        else
        {
            byte[] bytes1 = value.getBytes();
            byte[] bytes2 = that.value.getBytes();

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
                    comp = value.compareTo( ( Value ) that.value );

                    return comp;
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
                    comp = value.compareTo( that.value );

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
