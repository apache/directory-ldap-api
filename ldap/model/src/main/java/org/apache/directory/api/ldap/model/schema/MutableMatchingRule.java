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


import org.apache.directory.api.i18n.I18n;


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
public class MutableMatchingRule extends MatchingRule
{
    /** The mandatory serialVersionUID */
    public static final long serialVersionUID = 1L;


    /**
     * Creates a new instance of MatchingRule.
     *
     * @param oid The MatchingRule OID
     */
    public MutableMatchingRule( String oid )
    {
        super( oid );
    }


    /**
     * Sets the Syntax's OID
     *
     * @param oid The Syntax's OID
     */
    public void setSyntaxOid( String oid )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.ldapSyntaxOid = oid;
        }
    }


    /**
     * Sets the Syntax
     *
     * @param ldapSyntax The Syntax
     */
    public void setSyntax( LdapSyntax ldapSyntax )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.ldapSyntax = ldapSyntax;
            this.ldapSyntaxOid = ldapSyntax.getOid();
        }
    }


    /**
     * Update the associated Syntax, even if the SchemaObject is readOnly
     *
     * @param ldapSyntax The Syntax
     */
    public void updateSyntax( LdapSyntax ldapSyntax )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        this.ldapSyntax = ldapSyntax;
        this.ldapSyntaxOid = ldapSyntax.getOid();
    }


    /**
     * Sets the LdapComparator
     *
     * @param ldapComparator The LdapComparator
     */
    @SuppressWarnings("unchecked")
    public void setLdapComparator( LdapComparator<?> ldapComparator )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.ldapComparator = ( LdapComparator<? super Object> ) ldapComparator;
        }
    }


    /**
     * Update the associated Comparator, even if the SchemaObject is readOnly
     *
     * @param ldapComparator The LdapComparator
     */
    @SuppressWarnings("unchecked")
    public void updateLdapComparator( LdapComparator<?> ldapComparator )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        this.ldapComparator = ( LdapComparator<? super Object> ) ldapComparator;
    }


    /**
     * Sets the Normalizer
     *
     * @param normalizer The Normalizer
     */
    public void setNormalizer( Normalizer normalizer )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.normalizer = normalizer;
        }
    }


    /**
     * Update the associated Normalizer, even if the SchemaObject is readOnly
     *
     * @param normalizer The Normalizer
     */
    public void updateNormalizer( Normalizer normalizer )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        this.normalizer = normalizer;
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
        ldapComparator = null;
        ldapSyntax = null;
        normalizer = null;
    }
}
