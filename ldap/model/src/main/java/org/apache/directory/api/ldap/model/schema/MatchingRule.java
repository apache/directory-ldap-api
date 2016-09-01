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
package org.apache.directory.api.ldap.model.schema;




/**
 * A matchingRule definition. MatchingRules associate a comparator and a
 * normalizer, forming the basic tools necessary to assert actions against
 * attribute values. MatchingRules are associated with a specific Syntax for the
 * purpose of resolving a normalized form and for comparisons.
 * <p>
 * According to ldapbis [MODELS]:
 * </p>
 * 
 * <pre>
 *  4.1.3. Matching Rules
 * 
 *    Matching rules are used by servers to compare attribute values against
 *    assertion values when performing Search and Compare operations.  They
 *    are also used to identify the value to be added or deleted when
 *    modifying entries, and are used when comparing a purported
 *    distinguished name with the name of an entry.
 * 
 *    A matching rule specifies the syntax of the assertion value.
 * 
 *    Each matching rule is identified by an object identifier (OID) and,
 *    optionally, one or more short names (descriptors).
 * 
 *    Matching rule definitions are written according to the ABNF:
 * 
 *      MatchingRuleDescription = LPAREN WSP
 *          numericoid                ; object identifier
 *          [ SP &quot;NAME&quot; SP qdescrs ]  ; short names (descriptors)
 *          [ SP &quot;DESC&quot; SP qdstring ] ; description
 *          [ SP &quot;OBSOLETE&quot; ]         ; not active
 *          SP &quot;SYNTAX&quot; SP numericoid ; assertion syntax
 *          extensions WSP RPAREN     ; extensions
 * 
 *    where:
 *      [numericoid] is object identifier assigned to this matching rule;
 *      NAME [qdescrs] are short names (descriptors) identifying this
 *          matching rule;
 *      DESC [qdstring] is a short descriptive string;
 *      OBSOLETE indicates this matching rule is not active;
 *      SYNTAX identifies the assertion syntax by object identifier; and
 *      [extensions] describe extensions.
 * </pre>
 * 
 * @see <a href="http://www.faqs.org/rfcs/rfc2252.html">RFC 2252 Section 4.5</a>
 * @see <a
 *      href="http://www.ietf.org/internet-drafts/draft-ietf-ldapbis-models-11.txt">ldapbis
 *      [MODELS]</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class MatchingRule extends AbstractSchemaObject
{
    /** The mandatory serialVersionUID */
    public static final long serialVersionUID = 1L;

    /** The associated Comparator */
    protected LdapComparator<? super Object> ldapComparator;

    /** The associated Normalizer */
    protected Normalizer normalizer;

    /** The associated LdapSyntax */
    protected LdapSyntax ldapSyntax;

    /** The associated LdapSyntax OID */
    protected String ldapSyntaxOid;


    /**
     * Creates a new instance of MatchingRule.
     *
     * @param oid The MatchingRule OID
     */
    public MatchingRule( String oid )
    {
        super( SchemaObjectType.MATCHING_RULE, oid );
    }


    /**
     * Gets the LdapSyntax used by this MatchingRule.
     * 
     * @return the LdapSyntax of this MatchingRule
     */
    public LdapSyntax getSyntax()
    {
        return ldapSyntax;
    }


    /**
     * Gets the LdapSyntax OID used by this MatchingRule.
     * 
     * @return the LdapSyntax of this MatchingRule
     */
    public String getSyntaxOid()
    {
        return ldapSyntaxOid;
    }


    /**
     * Gets the LdapComparator enabling the use of this MatchingRule for ORDERING
     * and sorted indexing.
     * 
     * @return the ordering LdapComparator
     */
    public LdapComparator<? super Object> getLdapComparator()
    {
        return ldapComparator;
    }


    /**
     * Gets the Normalizer enabling the use of this MatchingRule for EQUALITY
     * matching and indexing.
     * 
     * @return the associated normalizer
     */
    public Normalizer getNormalizer()
    {
        return normalizer;
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
     * Copy an MatchingRule
     */
    @Override
    public MatchingRule copy()
    {
        MatchingRule copy = new MutableMatchingRule( oid );

        // Copy the SchemaObject common data
        copy.copy( this );

        // All the references to other Registries object are set to null.
        copy.ldapComparator = null;
        copy.ldapSyntax = null;
        copy.normalizer = null;

        // Copy the syntax OID
        copy.ldapSyntaxOid = ldapSyntaxOid;

        return copy;
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

        if ( !( o instanceof MatchingRule ) )
        {
            return false;
        }

        MatchingRule that = ( MatchingRule ) o;

        // Check the Comparator
        if ( ldapComparator != null )
        {
            if ( !ldapComparator.equals( that.ldapComparator ) )
            {
                return false;
            }
        }
        else
        {
            if ( that.ldapComparator != null )
            {
                return false;
            }
        }

        // Check the Normalizer
        if ( normalizer != null )
        {
            if ( !normalizer.equals( that.normalizer ) )
            {
                return false;
            }
        }
        else
        {
            if ( that.normalizer != null )
            {
                return false;
            }
        }

        // Check the Syntax OID
        if ( !compareOid( ldapSyntaxOid, that.ldapSyntaxOid ) )
        {
            return false;
        }

        // Check the Syntax
        if ( ldapSyntax != null )
        {
            if ( !ldapSyntax.equals( that.ldapSyntax ) )
            {
                return false;
            }
        }
        else
        {
            if ( that.ldapSyntax != null )
            {
                return false;
            }
        }

        return true;
    }
}
