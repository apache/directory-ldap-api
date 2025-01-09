/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 * 
 *    https://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * 
 */
package org.apache.directory.api.ldap.model.schema;


import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.i18n.I18n;


/**
 * Represents an LDAP MatchingRuleUseDescription defined in RFC 2252.
 * <p>
 * According to ldapbis [MODELS]:
 * </p>
 * 
 * <pre>
 *  Values of the matchingRuleUse list the attributes which are suitable
 *  for use with an extensible matching rule.
 * 
 *    Matching rule use descriptions are written according to the following
 *    ABNF:
 * 
 *      MatchingRuleUseDescription = LPAREN WSP
 *          numericoid                ; object identifier
 *          [ SP &quot;NAME&quot; SP qdescrs ]  ; short names (descriptors)
 *          [ SP &quot;DESC&quot; SP qdstring ] ; description
 *          [ SP &quot;OBSOLETE&quot; ]         ; not active
 *          SP &quot;APPLIES&quot; SP oids      ; attribute types
 *          extensions WSP RPAREN     ; extensions
 * 
 *    where:
 *      [numericoid] is the object identifier of the matching rule
 *          associated with this matching rule use description;
 *      NAME [qdescrs] are short names (descriptors) identifying this
 *          matching rule use;
 *      DESC [qdstring] is a short descriptive string;
 *      OBSOLETE indicates this matching rule use is not active;
 *      APPLIES provides a list of attribute types the matching rule applies
 *          to; and
 *      [extensions] describe extensions.
 * 
 *  The matchingRule within the MatchingRuleUse definition can be used by an
 *  extensible match assertion if the assertion is based on the attributes
 *  listed within the MatchingRuleUse definition.  If an extensible match
 *  assertion is based on attributes other than those listed within the
 *  MatchingRuleUse definition then the assertion is deemed undefined.
 * 
 *  Also according to 3.3.20 of [SYNTAXES] (ldapbis working group):
 * 
 *  A value of the Matching Rule Use Description syntax indicates the
 *  attribute types to which a matching rule may be applied in an
 *  extensibleMatch search filter [PROT].  The LDAP-specific encoding of
 *  a value of this syntax is defined by the &lt;MatchingRuleUseDescription&gt;
 *  rule in [MODELS] above.
 * </pre>
 * 
 * @see <a
 *      href="http://www.ietf.org/internet-drafts/draft-ietf-ldapbis-models-11.txt">ldapbis
 *      [MODELS]</a>
 * @see <a
 *      href="http://www.ietf.org/internet-drafts/draft-ietf-ldapbis-syntaxes-09.txt">ldapbis
 *      [SYNTAXES]</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class MatchingRuleUse extends AbstractSchemaObject
{
    /** Declares the Serial Version Uid */
    public static final long serialVersionUID = 1L;

    /** The list of attributes types OID the matching rule applies to */
    private List<String> applicableAttributeOids;

    /** The list of attributes types the matching rule applies to */
    private List<AttributeType> applicableAttributes;

    /**
     * Creates a new instance of MatchingRuleUseDescription
     * 
     * @param oid the MatchingRuleUse's OID
     */
    public MatchingRuleUse( String oid )
    {
        super( SchemaObjectType.MATCHING_RULE_USE, oid );

        applicableAttributeOids = new ArrayList<>();
        applicableAttributes = new ArrayList<>();
    }


    /**
     * @return The matchingRule's list of AttributeType OIDs the MRU applies to
     */
    public List<String> getApplicableAttributeOids()
    {
        return applicableAttributeOids;
    }


    /**
     * @return The matchingRule's list of AttributeType OIDs the MRU applies to
     */
    public List<AttributeType> getApplicableAttributes()
    {
        return applicableAttributes;
    }


    /**
     * Set the matchingRule's AttributeType OIDs the MRU applies to.
     *
     * @param applicableAttributeOids The AttributeType OIDs list
     */
    public void setApplicableAttributeOids( List<String> applicableAttributeOids )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.applicableAttributeOids = applicableAttributeOids;
    }


    /**
     * Set the matchingRule's AttributeType the MRU applies to.
     *
     * @param applicableAttributes The AttributeType list
     */
    public void setApplicableAttributes( List<AttributeType> applicableAttributes )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.applicableAttributes = applicableAttributes;

        // update the OIDS now
        applicableAttributeOids.clear();

        for ( AttributeType at : applicableAttributes )
        {
            applicableAttributeOids.add( at.getOid() );
        }
    }


    /**
     * Add a matchingRule's AttributeType OIDs the MRU applies to.
     *
     * @param oid A matchingRule's AttributeType OIDs the MRU applies to
     */
    public void addApplicableAttributeOids( String oid )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        if ( !applicableAttributeOids.contains( oid ) )
        {
            applicableAttributeOids.add( oid );
        }
    }


    /**
     * Add a matchingRule's AttributeType the MRU applies to.
     *
     * @param attributeType A matchingRule's AttributeType the MRU applies to
     */
    public void addApplicableAttribute( AttributeType attributeType )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        if ( !applicableAttributeOids.contains( attributeType.getOid() ) )
        {
            applicableAttributes.add( attributeType );
            applicableAttributeOids.add( attributeType.getOid() );
        }
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        return SchemaObjectRenderer.OPEN_LDAP_SCHEMA_RENDERER.render( this );
    }


    /**
     * Copy an MatchingRuleUse
     */
    @Override
    public MatchingRuleUse copy()
    {
        MatchingRuleUse copy = new MatchingRuleUse( oid );

        // Copy the SchemaObject common data
        copy.copy( this );

        // Clone the APPLY AttributeTypes
        copy.applicableAttributeOids = new ArrayList<>();

        // Copy the APPLIES oid list
        for ( String oid : applicableAttributeOids )
        {
            copy.applicableAttributeOids.add( oid );
        }

        // Copy the APPLIES list (will be empty)
        copy.applicableAttributes = new ArrayList<>();

        return copy;
    }

    
    /**
     * @see Object#equals(Object)
     */
    @Override
    public int hashCode()
    {
        int hash = h;
     
        if ( applicableAttributeOids != null )
        {
            int tempHash = 0;
            
            for ( String oid : applicableAttributeOids )
            {
                tempHash += oid.hashCode();
            }
            
            hash = hash * 17 + tempHash;
        }
        
        if ( applicableAttributes != null )
        {
            int tempHash = 0;

            for ( AttributeType attributeType : applicableAttributes )
            {
                tempHash += attributeType.hashCode();
            }

            hash = hash * 17 + tempHash;
        }

        return hash;
    }

    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals( Object o )
    {
        if ( !super.equals( o ) )
        {
            return false;
        }

        if ( !( o instanceof MatchingRuleUse ) )
        {
            return false;
        }

        @SuppressWarnings("unused")
        MatchingRuleUse that = ( MatchingRuleUse ) o;

        // TODO : complete the checks
        return true;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clear()
    {
        // Clear the common elements
        super.clear();

        // Clear the references
        applicableAttributes.clear();
        applicableAttributeOids.clear();
    }
}
