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
package org.apache.directory.shared.ldap.model.entry;

import org.apache.directory.shared.i18n.I18n;
import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.shared.ldap.model.message.ResultCodeEnum;
import org.apache.directory.shared.ldap.model.schema.AttributeType;
import org.apache.directory.shared.ldap.model.schema.LdapComparator;
import org.apache.directory.shared.ldap.model.schema.MatchingRule;
import org.apache.directory.shared.ldap.model.schema.Normalizer;
import org.apache.directory.shared.ldap.model.schema.SyntaxChecker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A wrapper around byte[] values in entries.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractValue<T> implements Value<T>
{
    /** logger for reporting errors that might not be handled properly upstream */
    protected static final Logger LOG = LoggerFactory.getLogger( AbstractValue.class );

    /** reference to the attributeType zssociated with the value */
    protected transient AttributeType attributeType;

    /** the wrapped binary value */
    protected T wrappedValue;
    
    /** the canonical representation of the wrapped value */
    protected T normalizedValue;

    /** A flag set when the value has been normalized */
    //protected boolean normalized;

    /** cached results of the isValid() method call */
    protected Boolean valid;

    /** A flag set if the normalized data is different from the wrapped data */
    protected boolean same;
    
    /** The computed hashcode. We don't want to compute it each time the hashcode() method is called */
    protected volatile int h;
    
    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    public Value<T> clone()
    {
        try
        {
            return (Value<T>)super.clone();
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
    public T getReference()
    {
        return wrappedValue;
    }

    
    /**
     * {@inheritDoc}
     */
    public AttributeType getAttributeType()
    {
        return attributeType;
    }

    
    /**
     * {@inheritDoc}
     */
    public void apply( AttributeType attributeType ) throws LdapInvalidAttributeValueException
    {
        if ( attributeType == null )
        {
            normalizedValue = wrappedValue;
            return;
        }
        
        this.attributeType = attributeType;
        
        try
        {
            MatchingRule equality = attributeType.getEquality();
            
            if ( equality != null )
            {
                Normalizer normalizer = equality.getNormalizer();
                
                if ( normalizer != null )
                {
                    if ( wrappedValue != null )
                    {
                        if ( isHR() )
                        {     
                            normalizedValue = (T)normalizer.normalize( (String)wrappedValue );
                        }
                        else
                        {
                            normalizedValue = (T)normalizer.normalize( new BinaryValue( (byte[])wrappedValue ) ).getNormReference();
                        }
                    }
                }
            }
        }
        catch ( LdapException ne )
        {
            String message = I18n.err( I18n.ERR_04447_CANNOT_NORMALIZE_VALUE, ne.getLocalizedMessage() );
            LOG.info( message );
        }
        
        // and checks that the value is syntaxically correct
        try
        {
            if ( ! isValid( attributeType.getSyntax().getSyntaxChecker() ) )
            {
                String message = I18n.err( I18n.ERR_04473_NOT_VALID_VALUE, wrappedValue );
                LOG.info( message );
                throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, message );
            }
        }
        catch ( LdapException le )
        {
            String message = I18n.err( I18n.ERR_04447_CANNOT_NORMALIZE_VALUE, le.getLocalizedMessage() );
            LOG.info( message );
            throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, message );
        }
        
        h=0;
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
            MatchingRule mr = getMatchingRule();
    
            if ( mr == null )
            {
                return null;
            }
    
            return (LdapComparator<T>)mr.getLdapComparator();
        }
        else
        {
            return null;
        }
    }
    
    
    /**
     * Find a matchingRule to use for normalization and comparison.  If an equality
     * matchingRule cannot be found it checks to see if other matchingRules are
     * available: SUBSTR, and ORDERING.  If a matchingRule cannot be found null is
     * returned.
     *
     * @return a matchingRule or null if one cannot be found for the attributeType
     * @throws LdapException if resolution of schema entities fail
     */
    protected final MatchingRule getMatchingRule() throws LdapException
    {
        if ( attributeType != null )
        {
            MatchingRule mr = attributeType.getEquality();
    
            if ( mr == null )
            {
                mr = attributeType.getOrdering();
            }
    
            if ( mr == null )
            {
                mr = attributeType.getSubstring();
            }
    
            return mr;
        }
        else
        {
            return null;
        }
    }


    /**
     * Gets a normalizer using getMatchingRule() to resolve the matchingRule
     * that the normalizer is extracted from.
     *
     * @return a normalizer associated with the attributeType or null if one cannot be found
     * @throws LdapException if resolution of schema entities fail
     */
    protected final Normalizer getNormalizer() throws LdapException
    {
        if ( attributeType != null )
        {
            MatchingRule mr = getMatchingRule();
    
            if ( mr == null )
            {
                return null;
            }
    
            return mr.getNormalizer();
        }
        else
        {
            return null;
        }
    }

    
    /**
     * {@inheritDoc}
     */
    public boolean instanceOf( AttributeType attributeType ) throws LdapException
    {
        if ( ( attributeType != null ) && this.attributeType.equals( attributeType ) )
        {
            if ( this.attributeType.equals( attributeType ) )
            {
                return true;
            }
            
            return this.attributeType.isDescendantOf( attributeType );
        }

        return false;
    }


    /**
     * {@inheritDoc}
     */
    public T getNormReference()
    {
        if ( isNull() )
        {
            return null;
        }

        if ( normalizedValue == null )
        {
            return wrappedValue;
        }

        return normalizedValue;
    }

    
    /**
     * {@inheritDoc}
     */
    public final boolean isNull()
    {
        return wrappedValue == null; 
    }
    
    
    /**
     * {@inheritDoc}
     */
    public final boolean isValid( SyntaxChecker syntaxChecker ) throws LdapException
    {
        if ( syntaxChecker == null )
        {
            String message = I18n.err( I18n.ERR_04139, toString() );
            LOG.error( message );
            throw new LdapException( message );
        }
        
        valid = syntaxChecker.isValidSyntax( normalizedValue );
        
        return valid;
    }


    /**
     * {@inheritDoc}
     */
    public final boolean isSchemaAware()
    {
        return attributeType != null;
    }
}