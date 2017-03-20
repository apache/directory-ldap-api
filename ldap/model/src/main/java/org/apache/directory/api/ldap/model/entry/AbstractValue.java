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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A wrapper around byte[] values in entries.
 * 
 * @param <T> The valye type
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractValue<T> implements Value<T>
{
    /** logger for reporting errors that might not be handled properly upstream */
    protected static final Logger LOG = LoggerFactory.getLogger( AbstractValue.class );

    /** reference to the attributeType zssociated with the value */
    protected transient AttributeType attributeType;

    /** the User Provided value */
    protected T upValue;

    /** the canonical representation of the user provided value */
    protected T normalizedValue;

    /** The computed hashcode. We don't want to compute it each time the hashcode() method is called */
    protected volatile int h;


    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    @Override
    public Value<T> clone()
    {
        try
        {
            return ( Value<T> ) super.clone();
        }
        catch ( CloneNotSupportedException cnse )
        {
            // Do nothing
            return null;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public T getReference()
    {
        return upValue;
    }


    /**
     * Get the wrapped value as a String.
     *
     * @return the wrapped value as a String
     */
    @Override
    public String getString()
    {
        throw new UnsupportedOperationException( "Cannot call this method on a binary value" );
    }


    /**
     * Get the wrapped value as a byte[].
     *
     * @return the wrapped value as a byte[]
     */
    @Override
    public byte[] getBytes()
    {
        throw new UnsupportedOperationException( "Cannot call this method on a String value" );
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
     * Apply an AttributeType to the current Value, normalizing it.
     *
     * @param attributeType The AttributeType to apply
     * @throws LdapInvalidAttributeValueException If the value is not valid accordingly
     * to the schema
     */
    @SuppressWarnings("unchecked")
    @Override
    public void apply( AttributeType attributeType ) throws LdapInvalidAttributeValueException
    {
        if ( this.attributeType != null )
        {
            // We already have applied an AttributeType, get out
            LOG.warn( "AttributeType {0} already applied", attributeType.getName() );
            return;
        }
        
        if ( attributeType == null )
        {
            // No attributeType : the normalized value and the user provided value are the same
            normalizedValue = upValue;
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

            if ( normalizer != null )
            {
                if ( upValue != null )
                {
                    boolean isHR = true;
                    // Some broken LDAP servers do not have proper syntax definitions
                    if ( attributeType.getSyntax() != null )
                    {
                        isHR = attributeType.getSyntax().isHumanReadable();
                    }
                    

                    if ( isHR != isHumanReadable() )
                    {
                        
                        String message = "The '" + attributeType.getName() + "' AttributeType and values must "
                            + "both be String or binary";
                        LOG.error( message );
                        throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, message );
                    }

                    try
                    {
                        if ( isHumanReadable() )
                        {
                            if ( normalizedValue != null )
                            {    
                                normalizedValue = ( T ) normalizer.normalize( ( String ) normalizedValue );
                            }
                            else
                            {
                                normalizedValue = ( T ) normalizer.normalize( ( String ) upValue );
                            }
                        }
                        else
                        {
                            normalizedValue = ( T ) normalizer.normalize( new BinaryValue( ( byte[] ) upValue ) )
                                .getNormReference();
                        }
                    }
                    catch ( LdapException ne )
                    {
                        String message = I18n.err( I18n.ERR_04447_CANNOT_NORMALIZE_VALUE, ne.getLocalizedMessage() );
                        LOG.info( message );
                    }
                }
            }
            else
            {
                String message = "The '" + attributeType.getName() + "' AttributeType does not have" + " a normalizer";
                LOG.error( message );
                throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, message );
            }
        }
        else
        {
            // No MatchingRule, there is nothing we can do but make the normalized value
            // to be a reference on the user provided value
            normalizedValue = upValue;
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
    @SuppressWarnings("unchecked")
    protected final LdapComparator<T> getLdapComparator() throws LdapException
    {
        if ( attributeType != null )
        {
            MatchingRule mr = attributeType.getEquality();

            if ( mr != null )
            {
                return ( LdapComparator<T> ) mr.getLdapComparator();
            }
        }

        return null;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isInstanceOf( AttributeType attributeType )
    {
        return ( attributeType != null )
            && ( this.attributeType.equals( attributeType ) || this.attributeType.isDescendantOf( attributeType ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public T getNormReference()
    {
        if ( isNull() )
        {
            return null;
        }

        if ( normalizedValue == null )
        {
            return upValue;
        }

        return normalizedValue;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public final boolean isNull()
    {
        return upValue == null;
    }


    /**
     * {@inheritDoc}
     */
    @Override
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
            return syntaxChecker.isValidSyntax( normalizedValue );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public final boolean isSchemaAware()
    {
        return attributeType != null;
    }
}