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
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An LDAP attribute.<p>
 * To define the kind of data stored, the client must set the isHR flag, or inject an AttributeType.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DefaultAttribute implements Attribute, Cloneable
{
    /** logger for reporting errors that might not be handled properly upstream */
    private static final Logger LOG = LoggerFactory.getLogger( DefaultAttribute.class );

    /** The associated AttributeType */
    private AttributeType attributeType;

    /** The set of contained values */
    private Set<Value<?>> values = new LinkedHashSet<>();

    /** The User provided ID */
    private String upId;

    /** The normalized ID (will be the OID if we have a AttributeType) */
    private String id;

    /** Tells if the attribute is Human Readable or not. When not set,
     * this flag is null. */
    private Boolean isHR;

    /** The computed hashcode. We don't want to compute it each time the hashcode() method is called */
    private volatile int h;


    //-------------------------------------------------------------------------
    // Constructors
    //-------------------------------------------------------------------------
    // maybe have some additional convenience constructors which take
    // an initial value as a string or a byte[]
    /**
     * Create a new instance of a Attribute, without ID nor value.
     * Used by the serializer
     */
    /* No protection*/DefaultAttribute()
    {
    }


    /**
     * Create a new instance of a schema aware Attribute, without ID nor value.
     * Used by the serializer
     */
    /* No protection*/DefaultAttribute( AttributeType attributeType, String upId, String normId, boolean isHR,
        int hashCode, Value<?>... values )
    {
        this.attributeType = attributeType;
        this.upId = upId;
        this.id = normId;
        this.isHR = isHR;
        this.h = hashCode;

        if ( values != null )
        {
            for ( Value<?> value : values )
            {
                this.values.add( value );
            }
        }
    }


    /**
     * Create a new instance of a schema aware Attribute, without ID nor value.
     * 
     * @param attributeType the attributeType for the empty attribute added into the entry
     */
    public DefaultAttribute( AttributeType attributeType )
    {
        if ( attributeType != null )
        {
            try
            {
                apply( attributeType );
            }
            catch ( LdapInvalidAttributeValueException liave )
            {
                // Do nothing, it can't happen, there is no value
            }
        }
    }


    /**
     * Create a new instance of an Attribute, without value.
     * @param upId The user provided ID
     */
    public DefaultAttribute( String upId )
    {
        setUpId( upId );
    }


    /**
     * Create a new instance of an Attribute, without value.
     * @param upId The user provided ID
     */
    public DefaultAttribute( byte[] upId )
    {
        setUpId( upId );
    }


    /**
     * Create a new instance of a schema aware Attribute, without value.
     * 
     * @param upId the ID for the added attributeType
     * @param attributeType the added AttributeType
     */
    public DefaultAttribute( String upId, AttributeType attributeType )
    {
        if ( attributeType == null )
        {
            String message = I18n.err( I18n.ERR_04460_ATTRIBUTE_TYPE_NULL_NOT_ALLOWED );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        try
        {
            apply( attributeType );
        }
        catch ( LdapInvalidAttributeValueException liave )
        {
            // Do nothing, it can't happen, there is no value
        }

        setUpId( upId, attributeType );
    }


    /**
     * Create a new instance of an Attribute, with some values, and a user provided ID.<br>
     * If the value does not correspond to the same attributeType, then it's
     * wrapped value is copied into a new ClientValue which uses the specified
     * attributeType.
     * <p>
     * Otherwise, the value is stored, but as a reference. It's not a copy.
     * </p>
     * @param upId the attributeType ID
     * @param vals an initial set of values for this attribute
     */
    public DefaultAttribute( String upId, Value<?>... vals )
    {
        // The value can be null, this is a valid value.
        if ( vals[0] == null )
        {
            add( new StringValue( ( String ) null ) );
        }
        else
        {
            for ( Value<?> val : vals )
            {
                if ( ( val instanceof StringValue ) || ( !val.isHumanReadable() ) )
                {
                    add( val );
                }
                else
                {
                    String message = I18n.err( I18n.ERR_04129, val.getClass().getName() );
                    LOG.error( message );
                    throw new IllegalStateException( message );
                }
            }
        }

        setUpId( upId );
    }


    /**
     * Create a new instance of a schema aware Attribute, without ID but with some values.
     * 
     * @param attributeType The attributeType added on creation
     * @param vals The added value for this attribute
     * @throws LdapInvalidAttributeValueException If any of the
     * added values is not valid
     */
    public DefaultAttribute( AttributeType attributeType, String... vals ) throws LdapInvalidAttributeValueException
    {
        this( null, attributeType, vals );
    }


    /**
     * Create a new instance of a schema aware Attribute, with some values, and a user provided ID.
     * 
     * @param upId the ID for the created attribute
     * @param attributeType The attributeType added on creation
     * @param vals the added values for this attribute
     * @throws LdapInvalidAttributeValueException If any of the
     * added values is not valid
     */
    public DefaultAttribute( String upId, AttributeType attributeType, String... vals )
        throws LdapInvalidAttributeValueException
    {
        if ( attributeType == null )
        {
            String message = I18n.err( I18n.ERR_04460_ATTRIBUTE_TYPE_NULL_NOT_ALLOWED );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        apply( attributeType );

        if ( ( vals != null ) && ( vals.length > 0 ) )
        {
            add( vals );
        }

        setUpId( upId, attributeType );
    }


    /**
     * Create a new instance of a schema aware Attribute, with some values, and a user provided ID.<br>
     * If the value does not correspond to the same attributeType, then it's
     * wrapped value is copied into a new Value which uses the specified
     * attributeType.
     * <p>
     * Otherwise, the value is stored, but as a reference. It's not a copy.
     * </p>
     * @param upId the ID of the created attribute
     * @param attributeType the attribute type according to the schema
     * @param vals an initial set of values for this attribute
     * @throws LdapInvalidAttributeValueException If any of the
     * added values is not valid
     */
    public DefaultAttribute( String upId, AttributeType attributeType, Value<?>... vals )
        throws LdapInvalidAttributeValueException
    {
        if ( attributeType == null )
        {
            String message = I18n.err( I18n.ERR_04460_ATTRIBUTE_TYPE_NULL_NOT_ALLOWED );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        apply( attributeType );
        setUpId( upId, attributeType );
        add( vals );
    }


    /**
     * Create a new instance of a schema aware Attribute, with some values.
     * <p>
     * If the value does not correspond to the same attributeType, then it's
     * wrapped value is copied into a new Value which uses the specified
     * attributeType.
     * </p>
     * @param attributeType the attribute type according to the schema
     * @param vals an initial set of values for this attribute
     * @throws LdapInvalidAttributeValueException If one the values are invalid
     */
    public DefaultAttribute( AttributeType attributeType, Value<?>... vals ) throws LdapInvalidAttributeValueException
    {
        this( null, attributeType, vals );
    }


    /**
     * Create a new instance of an Attribute, with some String values, and a user provided ID.
     * 
     * @param upId the ID of the created attribute
     * @param vals an initial set of String values for this attribute
     */
    public DefaultAttribute( String upId, String... vals )
    {
        try
        {
            add( vals );
        }
        catch ( LdapInvalidAttributeValueException liave )
        {
            // Do nothing, it can't happen
        }

        setUpId( upId );
    }


    /**
     * Create a new instance of an Attribute, with some binary values, and a user provided ID.
     * 
     * @param upId the ID of the created attribute
     * @param vals an initial set of binary values for this attribute
     */
    public DefaultAttribute( String upId, byte[]... vals )
    {
        try
        {
            add( vals );
        }
        catch ( LdapInvalidAttributeValueException liave )
        {
            // Do nothing, this can't happen
        }

        setUpId( upId );
    }


    /**
     * Create a new instance of a schema aware Attribute, with some byte[] values.
     * 
     * @param attributeType The attributeType added on creation
     * @param vals The added binary values
     * @throws LdapInvalidAttributeValueException If any of the
     * added values is not valid
     */
    public DefaultAttribute( AttributeType attributeType, byte[]... vals ) throws LdapInvalidAttributeValueException
    {
        this( null, attributeType, vals );
    }


    /**
     * Create a new instance of a schema aware Attribute, with some byte[] values, and
     * a user provided ID.
     * 
     * @param upId the ID for the added attribute
     * @param attributeType the AttributeType to be added
     * @param vals the binary values for the added attribute
     * @throws LdapInvalidAttributeValueException If any of the
     * added values is not valid
     */
    public DefaultAttribute( String upId, AttributeType attributeType, byte[]... vals )
        throws LdapInvalidAttributeValueException
    {
        if ( attributeType == null )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04460_ATTRIBUTE_TYPE_NULL_NOT_ALLOWED ) );
        }

        apply( attributeType );
        add( vals );
        setUpId( upId, attributeType );
    }


    /**
     * Creates a new instance of schema aware Attribute, by copying another attribute.
     * If the initial Attribute is not schema aware, the copy will be if the attributeType
     * argument is not null.
     *
     * @param attributeType The attribute's type
     * @param attribute The attribute to be copied
     * @throws LdapException If we weren't able to create an instance
     */
    public DefaultAttribute( AttributeType attributeType, Attribute attribute ) throws LdapException
    {
        // Copy the common values. isHR is only available on a ServerAttribute
        this.attributeType = attributeType;
        this.id = attribute.getId();
        this.upId = attribute.getUpId();

        if ( attributeType == null )
        {
            isHR = attribute.isHumanReadable();

            // Copy all the values
            for ( Value<?> value : attribute )
            {
                add( value.clone() );
            }

            if ( attribute.getAttributeType() != null )
            {
                apply( attribute.getAttributeType() );
            }
        }
        else
        {

            isHR = attributeType.getSyntax().isHumanReadable();

            // Copy all the values
            for ( Value<?> clientValue : attribute )
            {
                Value<?> serverValue = null;

                // We have to convert the value first
                if ( clientValue instanceof StringValue )
                {
                    if ( isHR )
                    {
                        serverValue = new StringValue( attributeType, clientValue.getString() );
                    }
                    else
                    {
                        // We have to convert the value to a binary value first
                        serverValue = new BinaryValue( attributeType,
                            clientValue.getBytes() );
                    }
                }
                else if ( clientValue instanceof BinaryValue )
                {
                    if ( isHR )
                    {
                        // We have to convert the value to a String value first
                        serverValue = new StringValue( attributeType,
                            clientValue.getString() );
                    }
                    else
                    {
                        serverValue = new BinaryValue( attributeType, clientValue.getBytes() );
                    }
                }

                add( serverValue );
            }
        }
    }


    //-------------------------------------------------------------------------
    // Helper methods
    //-------------------------------------------------------------------------
    private Value<String> createStringValue( AttributeType attributeType, String value )
    {
        Value<String> stringValue;

        if ( attributeType != null )
        {
            try
            {
                stringValue = new StringValue( attributeType, value );
            }
            catch ( LdapInvalidAttributeValueException iae )
            {
                return null;
            }
        }
        else
        {
            stringValue = new StringValue( value );
        }

        return stringValue;
    }


    private Value<byte[]> createBinaryValue( AttributeType attributeType, byte[] value )
        throws LdapInvalidAttributeValueException
    {
        Value<byte[]> binaryValue;

        if ( attributeType != null )
        {
            binaryValue = new BinaryValue( attributeType, value );
        }
        else
        {
            binaryValue = new BinaryValue( value );
        }

        return binaryValue;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getBytes() throws LdapInvalidAttributeValueException
    {
        Value<?> value = get();

        if ( !isHR && ( value != null ) )
        {
            return value.getBytes();
        }

        String message = I18n.err( I18n.ERR_04130 );
        LOG.error( message );
        throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, message );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getString() throws LdapInvalidAttributeValueException
    {
        Value<?> value = get();

        if ( isHR && ( value != null ) )
        {
            return value.getString();
        }

        String message = I18n.err( I18n.ERR_04131 );
        LOG.error( message );
        throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, message );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getId()
    {
        return id;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getUpId()
    {
        return upId;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setUpId( String upId )
    {
        setUpId( upId, attributeType );
    }


    /**
     * Sets the User Provided ID as a byte[]
     * 
     * @param upId The User Provided ID
     */
    public void setUpId( byte[] upId )
    {
        setUpId( upId, attributeType );
    }


    /**
     * Check that the upId is either a name or the OID of a given AT
     */
    private boolean areCompatible( String id, AttributeType attributeType )
    {
        // First, get rid of the options, if any
        int optPos = id.indexOf( ';' );
        String idNoOption = id;

        if ( optPos != -1 )
        {
            idNoOption = id.substring( 0, optPos );
        }

        // Check that we find the ID in the AT names
        for ( String name : attributeType.getNames() )
        {
            if ( name.equalsIgnoreCase( idNoOption ) )
            {
                return true;
            }
        }

        // Not found in names, check the OID
        return Oid.isOid( id ) && attributeType.getOid().equals( id );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setUpId( String upId, AttributeType attributeType )
    {
        String trimmed = Strings.trim( upId );

        if ( Strings.isEmpty( trimmed ) && ( attributeType == null ) )
        {
            throw new IllegalArgumentException( "Cannot set a null ID with a null AttributeType" );
        }

        String newId = Strings.toLowerCaseAscii( trimmed );

        setUpIdInternal( upId, newId, attributeType );
    }


    /**
     * Sets the User Provided ID as a byte[]
     * 
     * @param upId The User Provided ID
     * @param attributeType The asscoiated AttributeType
     */
    public void setUpId( byte[] upId, AttributeType attributeType )
    {
        byte[] trimmed = Strings.trim( upId );

        if ( Strings.isEmpty( trimmed ) && ( attributeType == null ) )
        {
            throw new IllegalArgumentException( "Cannot set a null ID with a null AttributeType" );
        }

        String newId = Strings.toLowerCase( trimmed );

        setUpIdInternal( Strings.utf8ToString( upId ), newId, attributeType );
    }


    private void setUpIdInternal( String upId, String newId, AttributeType attributeType )
    {
        if ( attributeType == null )
        {
            if ( this.attributeType == null )
            {
                this.upId = upId;
                this.id = newId;

                // Compute the hashCode
                rehash();

                return;
            }
            else
            {
                if ( areCompatible( newId, this.attributeType ) )
                {
                    this.upId = upId;
                    this.id = this.attributeType.getOid();

                    // Compute the hashCode
                    rehash();

                    return;
                }
                else
                {
                    return;
                }
            }
        }

        if ( Strings.isEmpty( newId ) )
        {
            this.attributeType = attributeType;
            this.upId = attributeType.getName();
            this.id = attributeType.getOid();

            // Compute the hashCode
            rehash();

            return;
        }

        if ( areCompatible( newId, attributeType ) )
        {
            this.upId = upId;
            this.id = attributeType.getOid();
            this.attributeType = attributeType;

            // Compute the hashCode
            rehash();

            return;
        }

        throw new IllegalArgumentException( "ID '" + id + "' and AttributeType '" + attributeType.getName()
            + "' are not compatible " );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isHumanReadable()
    {
        return isHR != null ? isHR : false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isValid( AttributeType attributeType ) throws LdapInvalidAttributeValueException
    {
        LdapSyntax syntax = attributeType.getSyntax();

        if ( syntax == null )
        {
            return false;
        }

        SyntaxChecker syntaxChecker = syntax.getSyntaxChecker();

        if ( syntaxChecker == null )
        {
            return false;
        }

        // Check that we can have no value for this attributeType
        if ( values.isEmpty() )
        {
            return syntaxChecker.isValidSyntax( null );
        }

        // Check that we can't have more than one value if the AT is single-value
        if ( ( attributeType.isSingleValued() ) && ( values.size() > 1 ) )
        {
            return false;
        }

        // Now check the values
        for ( Value<?> value : values )
        {
            try
            {
                if ( !value.isValid( syntaxChecker ) )
                {
                    return false;
                }
            }
            catch ( LdapException le )
            {
                return false;
            }
        }

        return true;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int add( Value<?>... vals )
    {
        int nbAdded = 0;
        BinaryValue nullBinaryValue = null;
        StringValue nullStringValue = null;
        boolean nullValueAdded = false;
        Value<?>[] valArray = vals;

        if ( vals == null )
        {
            valArray = new Value[0];
        }

        if ( attributeType != null )
        {
            for ( Value<?> val : valArray )
            {
                if ( attributeType.getSyntax().isHumanReadable() )
                {
                    if ( ( val == null ) || val.isNull() )
                    {
                        try
                        {
                            Value<String> nullSV = new StringValue( attributeType, ( String ) null );

                            if ( values.add( nullSV ) )
                            {
                                nbAdded++;
                            }
                        }
                        catch ( LdapInvalidAttributeValueException iae )
                        {
                            continue;
                        }
                    }
                    else if ( val instanceof StringValue )
                    {
                        StringValue stringValue = ( StringValue ) val;

                        try
                        {
                            if ( stringValue.getAttributeType() == null )
                            {
                                stringValue.apply( attributeType );
                            }

                            if ( values.contains( val ) )
                            {
                                // Replace the value
                                values.remove( val );
                                values.add( val );
                            }
                            else if ( values.add( val ) )
                            {
                                nbAdded++;
                            }
                        }
                        catch ( LdapInvalidAttributeValueException iae )
                        {
                            continue;
                        }
                    }
                    else
                    {
                        String message = I18n.err( I18n.ERR_04451 );
                        LOG.error( message );
                    }
                }
                else
                {
                    if ( val == null )
                    {
                        if ( attributeType.getSyntax().getSyntaxChecker().isValidSyntax( val ) )
                        {
                            try
                            {
                                Value<byte[]> nullSV = new BinaryValue( attributeType, ( byte[] ) null );

                                if ( values.add( nullSV ) )
                                {
                                    nbAdded++;
                                }
                            }
                            catch ( LdapInvalidAttributeValueException iae )
                            {
                                continue;
                            }
                        }
                        else
                        {
                            String message = I18n.err( I18n.ERR_04452 );
                            LOG.error( message );
                        }
                    }
                    else
                    {
                        if ( val instanceof BinaryValue )
                        {
                            BinaryValue binaryValue = ( BinaryValue ) val;

                            try
                            {
                                if ( binaryValue.getAttributeType() == null )
                                {
                                    binaryValue = new BinaryValue( attributeType, val.getBytes() );
                                }

                                if ( values.add( binaryValue ) )
                                {
                                    nbAdded++;
                                }
                            }
                            catch ( LdapInvalidAttributeValueException iae )
                            {
                                continue;
                            }
                        }
                        else
                        {
                            String message = I18n.err( I18n.ERR_04452 );
                            LOG.error( message );
                        }
                    }
                }
            }
        }
        else
        {
            for ( Value<?> val : valArray )
            {
                if ( val == null )
                {
                    // We have a null value. If the HR flag is not set, we will consider
                    // that the attribute is not HR. We may change this later
                    if ( isHR == null )
                    {
                        // This is the first value. Add both types, as we
                        // don't know yet the attribute type's, but we may
                        // know later if we add some new value.
                        // We have to do that because we are using a Set,
                        // and we can't remove the first element of the Set.
                        nullBinaryValue = new BinaryValue( ( byte[] ) null );
                        nullStringValue = new StringValue( ( String ) null );

                        values.add( nullBinaryValue );
                        values.add( nullStringValue );
                        nullValueAdded = true;
                        nbAdded++;
                    }
                    else if ( !isHR )
                    {
                        // The attribute type is binary.
                        nullBinaryValue = new BinaryValue( ( byte[] ) null );

                        // Don't add a value if it already exists.
                        if ( !values.contains( nullBinaryValue ) )
                        {
                            values.add( nullBinaryValue );
                            nbAdded++;
                        }

                    }
                    else
                    {
                        // The attribute is HR
                        nullStringValue = new StringValue( ( String ) null );

                        // Don't add a value if it already exists.
                        if ( !values.contains( nullStringValue ) )
                        {
                            values.add( nullStringValue );
                        }
                    }
                }
                else
                {
                    // Let's check the value type.
                    if ( val instanceof StringValue )
                    {
                        // We have a String value
                        if ( isHR == null )
                        {
                            // The attribute type will be set to HR
                            isHR = true;
                            values.add( val );
                            nbAdded++;
                        }
                        else if ( !isHR )
                        {
                            // The attributeType is binary, convert the
                            // value to a BinaryValue
                            BinaryValue bv = new BinaryValue( val.getBytes() );

                            if ( !contains( bv ) )
                            {
                                values.add( bv );
                                nbAdded++;
                            }
                        }
                        else
                        {
                            // The attributeType is HR, simply add the value
                            if ( !contains( val ) )
                            {
                                values.add( val );
                                nbAdded++;
                            }
                        }
                    }
                    else
                    {
                        // We have a Binary value
                        if ( isHR == null )
                        {
                            // The attribute type will be set to binary
                            isHR = false;
                            values.add( val );
                            nbAdded++;
                        }
                        else if ( !isHR )
                        {
                            // The attributeType is not HR, simply add the value if it does not already exist
                            if ( !contains( val ) )
                            {
                                values.add( val );
                                nbAdded++;
                            }
                        }
                        else
                        {
                            // The attribute Type is HR, convert the
                            // value to a StringValue
                            StringValue sv = new StringValue( val.getString() );

                            if ( !contains( sv ) )
                            {
                                values.add( sv );
                                nbAdded++;
                            }
                        }
                    }
                }
            }
        }

        // Last, not least, if a nullValue has been added, and if other
        // values are all String, we have to keep the correct nullValue,
        // and to remove the other
        if ( nullValueAdded )
        {
            if ( isHR )
            {
                // Remove the Binary value
                values.remove( nullBinaryValue );
            }
            else
            {
                // Remove the String value
                values.remove( nullStringValue );
            }
        }

        return nbAdded;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int add( String... vals ) throws LdapInvalidAttributeValueException
    {
        int nbAdded = 0;
        String[] valArray = vals;

        if ( vals == null )
        {
            valArray = new String[0];
        }

        // First, if the isHR flag is not set, we assume that the
        // attribute is HR, because we are asked to add some strings.
        if ( isHR == null )
        {
            isHR = true;
        }

        // Check the attribute type.
        if ( attributeType == null )
        {
            if ( isHR )
            {
                for ( String val : valArray )
                {
                    Value<String> value = createStringValue( attributeType, val );

                    if ( value == null )
                    {
                        // The value can't be normalized : we don't add it.
                        LOG.error( I18n.err( I18n.ERR_04449, val ) );
                        continue;
                    }

                    // Call the add(Value) method, if not already present
                    if ( add( value ) == 1 )
                    {
                        nbAdded++;
                    }
                    else
                    {
                        LOG.warn( I18n.err( I18n.ERR_04486_VALUE_ALREADY_EXISTS, val, upId ) );
                    }
                }
            }
            else
            {
                // The attribute is binary. Transform the String to byte[]
                for ( String val : valArray )
                {
                    byte[] valBytes = null;

                    if ( val != null )
                    {
                        valBytes = Strings.getBytesUtf8( val );
                    }

                    Value<byte[]> value = createBinaryValue( attributeType, valBytes );

                    // Now call the add(Value) method
                    if ( add( value ) == 1 )
                    {
                        nbAdded++;
                    }
                }
            }
        }
        else
        {
            if ( attributeType.isSingleValued() && ( values.size() + valArray.length > 1 ) )
            {
                LOG.error( I18n.err( I18n.ERR_04487_ATTRIBUTE_IS_SINGLE_VALUED, attributeType.getName() ) );
                return 0;
            }

            if ( isHR )
            {
                for ( String val : valArray )
                {
                    Value<String> value = createStringValue( attributeType, val );

                    if ( value == null )
                    {
                        // The value can't be normalized : we don't add it.
                        LOG.error( I18n.err( I18n.ERR_04449, val ) );
                        continue;
                    }

                    // Call the add(Value) method, if not already present
                    if ( add( value ) == 1 )
                    {
                        nbAdded++;
                    }
                    else
                    {
                        LOG.warn( I18n.err( I18n.ERR_04486_VALUE_ALREADY_EXISTS, val, upId ) );
                    }
                }
            }
            else
            {
                // The attribute is binary. Transform the String to byte[]
                for ( String val : valArray )
                {
                    byte[] valBytes = null;

                    if ( val != null )
                    {
                        valBytes = Strings.getBytesUtf8( val );
                    }

                    Value<byte[]> value = createBinaryValue( attributeType, valBytes );

                    // Now call the add(Value) method
                    if ( add( value ) == 1 )
                    {
                        nbAdded++;
                    }
                }
            }
        }

        return nbAdded;
    }


    /**
     * {@inheritDoc}
     */
    public int add( byte[]... vals ) throws LdapInvalidAttributeValueException
    {
        int nbAdded = 0;
        byte[][] valArray = vals;

        if ( vals == null )
        {
            valArray = new byte[0][];
        }

        // First, if the isHR flag is not set, we assume that the
        // attribute is not HR, because we are asked to add some byte[].
        if ( isHR == null )
        {
            isHR = false;
        }

        if ( !isHR )
        {
            for ( byte[] val : valArray )
            {
                Value<byte[]> value;

                if ( attributeType == null )
                {
                    value = new BinaryValue( val );
                }
                else
                {
                    value = createBinaryValue( attributeType, val );
                }

                if ( add( value ) != 0 )
                {
                    nbAdded++;
                }
                else
                {
                    LOG.warn( I18n.err( I18n.ERR_04486_VALUE_ALREADY_EXISTS, Strings.dumpBytes( val ), upId ) );
                }
            }
        }
        else
        {
            // We can't add Binary values into a String Attribute
            LOG.info( I18n.err( I18n.ERR_04451 ) );
            return 0;
        }

        return nbAdded;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clear()
    {
        values.clear();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean contains( Value<?>... vals )
    {
        if ( isHR == null )
        {
            // If this flag is null, then there is no values.
            return false;
        }

        if ( attributeType == null )
        {
            if ( isHR )
            {
                // Iterate through all the values, convert the Binary values
                // to String values, and quit id any of the values is not
                // contained in the object
                for ( Value<?> val : vals )
                {
                    if ( val instanceof StringValue )
                    {
                        if ( !values.contains( val ) )
                        {
                            return false;
                        }
                    }
                    else
                    {
                        byte[] binaryVal = val.getBytes();

                        // We have to convert the binary value to a String
                        if ( !values.contains( new StringValue( Strings.utf8ToString( binaryVal ) ) ) )
                        {
                            return false;
                        }
                    }
                }
            }
            else
            {
                // Iterate through all the values, convert the String values
                // to binary values, and quit id any of the values is not
                // contained in the object
                for ( Value<?> val : vals )
                {
                    if ( val.isHumanReadable() )
                    {
                        String stringVal = val.getString();

                        // We have to convert the binary value to a String
                        if ( !values.contains( new BinaryValue( Strings.getBytesUtf8( stringVal ) ) ) )
                        {
                            return false;
                        }
                    }
                    else
                    {
                        if ( !values.contains( val ) )
                        {
                            return false;
                        }
                    }
                }
            }
        }
        else
        {
            // Iterate through all the values, and quit if we
            // don't find one in the values. We have to separate the check
            // depending on the isHR flag value.
            if ( isHR )
            {
                for ( Value<?> val : vals )
                {
                    if ( val instanceof StringValue )
                    {
                        StringValue stringValue = ( StringValue ) val;

                        try
                        {
                            if ( stringValue.getAttributeType() == null )
                            {
                                stringValue.apply( attributeType );
                            }
                        }
                        catch ( LdapInvalidAttributeValueException liave )
                        {
                            return false;
                        }

                        if ( !values.contains( val ) )
                        {
                            return false;
                        }
                    }
                    else
                    {
                        // Not a String value
                        return false;
                    }
                }
            }
            else
            {
                for ( Value<?> val : vals )
                {
                    if ( val instanceof BinaryValue )
                    {
                        if ( !values.contains( val ) )
                        {
                            return false;
                        }
                    }
                    else
                    {
                        // Not a Binary value
                        return false;
                    }
                }
            }
        }

        return true;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean contains( String... vals )
    {
        if ( isHR == null )
        {
            // If this flag is null, then there is no values.
            return false;
        }

        if ( attributeType == null )
        {
            if ( isHR )
            {
                for ( String val : vals )
                {
                    try
                    {
                        if ( !contains( new StringValue( val ) ) )
                        {
                            return false;
                        }
                    }
                    catch ( IllegalArgumentException iae )
                    {
                        return false;
                    }
                }
            }
            else
            {
                // As the attribute type is binary, we have to convert
                // the values before checking for them in the values
                // Iterate through all the values, and quit if we
                // don't find one in the values
                for ( String val : vals )
                {
                    byte[] binaryVal = Strings.getBytesUtf8( val );

                    if ( !contains( new BinaryValue( binaryVal ) ) )
                    {
                        return false;
                    }
                }
            }
        }
        else
        {
            if ( isHR )
            {
                // Iterate through all the values, and quit if we
                // don't find one in the values
                for ( String val : vals )
                {
                    try
                    {
                        StringValue value = new StringValue( attributeType, val );

                        if ( !values.contains( value ) )
                        {
                            return false;
                        }
                    }
                    catch ( LdapInvalidAttributeValueException liave )
                    {
                        return false;
                    }
                }

                return true;
            }
            else
            {
                return false;
            }
        }

        return true;
    }


    /**
     * {@inheritDoc}
     */
    public boolean contains( byte[]... vals )
    {
        if ( isHR == null )
        {
            // If this flag is null, then there is no values.
            return false;
        }

        if ( attributeType == null )
        {
            if ( !isHR )
            {
                // Iterate through all the values, and quit if we
                // don't find one in the values
                for ( byte[] val : vals )
                {
                    if ( !contains( new BinaryValue( val ) ) )
                    {
                        return false;
                    }
                }
            }
            else
            {
                // As the attribute type is String, we have to convert
                // the values before checking for them in the values
                // Iterate through all the values, and quit if we
                // don't find one in the values
                for ( byte[] val : vals )
                {
                    String stringVal = Strings.utf8ToString( val );

                    if ( !contains( new StringValue( stringVal ) ) )
                    {
                        return false;
                    }
                }
            }
        }
        else
        {
            if ( !isHR )
            {
                // Iterate through all the values, and quit if we
                // don't find one in the values
                for ( byte[] val : vals )
                {
                    try
                    {
                        BinaryValue value = new BinaryValue( attributeType, val );

                        if ( !values.contains( value ) )
                        {
                            return false;
                        }
                    }
                    catch ( LdapInvalidAttributeValueException liave )
                    {
                        return false;
                    }
                }

                return true;
            }
            else
            {
                return false;
            }
        }

        return true;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Value<?> get()
    {
        if ( values.isEmpty() )
        {
            return null;
        }

        return values.iterator().next();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int size()
    {
        return values.size();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean remove( Value<?>... vals )
    {
        if ( ( isHR == null ) || values.isEmpty() )
        {
            // Trying to remove a value from an empty list will fail
            return false;
        }

        boolean removed = true;

        if ( attributeType == null )
        {
            if ( isHR )
            {
                for ( Value<?> val : vals )
                {
                    if ( val instanceof StringValue )
                    {
                        removed &= values.remove( val );
                    }
                    else
                    {
                        // Convert the binary value to a string value
                        byte[] binaryVal = val.getBytes();
                        removed &= values.remove( new StringValue( Strings.utf8ToString( binaryVal ) ) );
                    }
                }
            }
            else
            {
                for ( Value<?> val : vals )
                {
                    removed &= values.remove( val );
                }
            }
        }
        else
        {
            // Loop through all the values to remove. If one of
            // them is not present, the method will return false.
            // As the attribute may be HR or not, we have two separated treatments
            if ( isHR )
            {
                for ( Value<?> val : vals )
                {
                    if ( val instanceof StringValue )
                    {
                        StringValue stringValue = ( StringValue ) val;

                        try
                        {
                            if ( stringValue.getAttributeType() == null )
                            {
                                stringValue.apply( attributeType );
                            }

                            removed &= values.remove( stringValue );
                        }
                        catch ( LdapInvalidAttributeValueException liave )
                        {
                            removed = false;
                        }
                    }
                    else
                    {
                        removed = false;
                    }
                }
            }
            else
            {
                for ( Value<?> val : vals )
                {
                    if ( val instanceof BinaryValue )
                    {
                        try
                        {
                            BinaryValue binaryValue = ( BinaryValue ) val;

                            if ( binaryValue.getAttributeType() == null )
                            {
                                binaryValue.apply( attributeType );
                            }

                            removed &= values.remove( binaryValue );
                        }
                        catch ( LdapInvalidAttributeValueException liave )
                        {
                            removed = false;
                        }
                    }
                    else
                    {
                        removed = false;
                    }
                }
            }
        }

        return removed;
    }


    /**
     * {@inheritDoc}
     */
    public boolean remove( byte[]... vals )
    {
        if ( ( isHR == null ) || values.isEmpty() )
        {
            // Trying to remove a value from an empty list will fail
            return false;
        }

        boolean removed = true;

        if ( attributeType == null )
        {
            if ( !isHR )
            {
                // The attribute type is not HR, we can directly process the values
                for ( byte[] val : vals )
                {
                    BinaryValue value = new BinaryValue( val );
                    removed &= values.remove( value );
                }
            }
            else
            {
                // The attribute type is String, we have to convert the values
                // to String before removing them
                for ( byte[] val : vals )
                {
                    StringValue value = new StringValue( Strings.utf8ToString( val ) );
                    removed &= values.remove( value );
                }
            }
        }
        else
        {
            if ( !isHR )
            {
                try
                {
                    for ( byte[] val : vals )
                    {
                        BinaryValue value = new BinaryValue( attributeType, val );
                        removed &= values.remove( value );
                    }
                }
                catch ( LdapInvalidAttributeValueException liave )
                {
                    removed = false;
                }
            }
            else
            {
                removed = false;
            }
        }

        return removed;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean remove( String... vals )
    {
        if ( ( isHR == null ) || values.isEmpty() )
        {
            // Trying to remove a value from an empty list will fail
            return false;
        }

        boolean removed = true;

        if ( attributeType == null )
        {
            if ( isHR )
            {
                // The attribute type is HR, we can directly process the values
                for ( String val : vals )
                {
                    StringValue value = new StringValue( val );
                    removed &= values.remove( value );
                }
            }
            else
            {
                // The attribute type is binary, we have to convert the values
                // to byte[] before removing them
                for ( String val : vals )
                {
                    BinaryValue value = new BinaryValue( Strings.getBytesUtf8( val ) );
                    removed &= values.remove( value );
                }
            }
        }
        else
        {
            if ( isHR )
            {
                for ( String val : vals )
                {
                    try
                    {
                        StringValue value = new StringValue( attributeType, val );
                        removed &= values.remove( value );
                    }
                    catch ( LdapInvalidAttributeValueException liave )
                    {
                        removed = false;
                    }
                }
            }
            else
            {
                removed = false;
            }
        }

        return removed;
    }


    /**
     * An iterator on top of the stored values.
     * 
     * @return an iterator over the stored values.
     */
    @Override
    public Iterator<Value<?>> iterator()
    {
        return values.iterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AttributeType getAttributeType()
    {
        return attributeType;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void apply( AttributeType attributeType ) throws LdapInvalidAttributeValueException
    {
        if ( attributeType == null )
        {
            throw new IllegalArgumentException( "The AttributeType parameter should not be null" );
        }

        this.attributeType = attributeType;
        this.id = attributeType.getOid();

        if ( Strings.isEmpty( this.upId ) )
        {
            this.upId = attributeType.getName();
        }
        else
        {
            if ( !areCompatible( this.upId, attributeType ) )
            {
                this.upId = attributeType.getName();
            }
        }

        if ( values != null )
        {
            Set<Value<?>> newValues = new LinkedHashSet<>( values.size() );

            for ( Value<?> value : values )
            {
                if ( value instanceof StringValue )
                {
                    newValues.add( new StringValue( attributeType, value.getString() ) );
                }
                else
                {
                    newValues.add( new BinaryValue( attributeType, value.getBytes() ) );
                }
            }

            values = newValues;
        }

        isHR = attributeType.getSyntax().isHumanReadable();

        // Compute the hashCode
        rehash();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isInstanceOf( AttributeType attributeType ) throws LdapInvalidAttributeValueException
    {
        return ( attributeType != null )
            && ( this.attributeType.equals( attributeType ) || this.attributeType.isDescendantOf( attributeType ) );
    }


    //-------------------------------------------------------------------------
    // Overloaded Object classes
    //-------------------------------------------------------------------------
    /**
     * A helper method to rehash the hashCode
     */
    private void rehash()
    {
        h = 37;

        if ( isHR != null )
        {
            h = h * 17 + isHR.hashCode();
        }

        if ( id != null )
        {
            h = h * 17 + id.hashCode();
        }

        if ( attributeType != null )
        {
            h = h * 17 + attributeType.hashCode();
        }
    }


    /**
     * The hashCode is based on the id, the isHR flag and
     * on the internal values.
     * 
     * @see Object#hashCode()
     * @return the instance's hashcode
     */
    @Override
    public int hashCode()
    {
        if ( h == 0 )
        {
            rehash();
        }

        return h;
    }


    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals( Object obj )
    {
        if ( obj == this )
        {
            return true;
        }

        if ( !( obj instanceof Attribute ) )
        {
            return false;
        }

        Attribute other = ( Attribute ) obj;

        if ( id == null )
        {
            if ( other.getId() != null )
            {
                return false;
            }
        }
        else
        {
            if ( other.getId() == null )
            {
                return false;
            }
            else
            {
                if ( attributeType != null )
                {
                    if ( !attributeType.equals( other.getAttributeType() ) )
                    {
                        return false;
                    }
                }
                else if ( !id.equals( other.getId() ) )
                {
                    return false;
                }
            }
        }

        if ( isHumanReadable() != other.isHumanReadable() )
        {
            return false;
        }

        if ( values.size() != other.size() )
        {
            return false;
        }

        for ( Value<?> val : values )
        {
            if ( !other.contains( val ) )
            {
                return false;
            }
        }

        if ( attributeType == null )
        {
            return other.getAttributeType() == null;
        }

        return attributeType.equals( other.getAttributeType() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Attribute clone()
    {
        try
        {
            DefaultAttribute attribute = ( DefaultAttribute ) super.clone();

            if ( this.attributeType != null )
            {
                attribute.id = attributeType.getOid();
                attribute.attributeType = attributeType;
            }

            attribute.values = new LinkedHashSet<>( values.size() );

            for ( Value<?> value : values )
            {
                // No need to clone the value, it will never be changed
                attribute.values.add( value );
            }

            return attribute;
        }
        catch ( CloneNotSupportedException cnse )
        {
            return null;
        }
    }


    /**
     * This is the place where we serialize attributes, and all theirs
     * elements.
     * 
     * {@inheritDoc}
     */
    @Override
    public void writeExternal( ObjectOutput out ) throws IOException
    {
        // Write the UPId (the id will be deduced from the upID)
        out.writeUTF( upId );

        // Write the HR flag, if not null
        if ( isHR != null )
        {
            out.writeBoolean( true );
            out.writeBoolean( isHR );
        }
        else
        {
            out.writeBoolean( false );
        }

        // Write the number of values
        out.writeInt( size() );

        if ( size() > 0 )
        {
            // Write each value
            for ( Value<?> value : values )
            {
                // Write the value
                value.writeExternal( out );
            }
        }

        out.flush();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void readExternal( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        // Read the ID and the UPId
        upId = in.readUTF();

        // Compute the id
        setUpId( upId );

        // Read the HR flag, if not null
        if ( in.readBoolean() )
        {
            isHR = in.readBoolean();
        }

        // Read the number of values
        int nbValues = in.readInt();

        if ( nbValues > 0 )
        {
            for ( int i = 0; i < nbValues; i++ )
            {
                Value<?> value;

                if ( isHR )
                {
                    value = new StringValue( attributeType );
                }
                else
                {
                    value = new BinaryValue( attributeType );
                }

                value.readExternal( in );

                values.add( value );
            }
        }
    }


    /**
     * @see Object#toString()
     */
    @Override
public String toString()
    {
        return toString( "" );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString( String tabs )
    {
        StringBuilder sb = new StringBuilder();

        if ( ( values != null ) && !values.isEmpty() )
        {
            boolean isFirst = true;

            for ( Value<?> value : values )
            {
                if ( isFirst )
                {
                    isFirst = false;
                }
                else
                {
                    sb.append( '\n' );
                }

                sb.append( tabs ).append( upId ).append( ": " );

                if ( value.isNull() )
                {
                    sb.append( "''" );
                }
                else
                {
                    sb.append( value );
                }
            }
        }
        else
        {
            sb.append( tabs ).append( upId ).append( ": (null)" );
        }

        return sb.toString();
    }
}
