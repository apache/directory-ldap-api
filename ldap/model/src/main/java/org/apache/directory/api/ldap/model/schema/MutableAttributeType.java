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
 * An attributeType specification. attributeType specifications describe the
 * nature of attributes within the directory. The attributeType specification's
 * properties are accessible through this interface.
 * <p>
 * According to ldapbis [MODELS]:
 * </p>
 *
 * <pre>
 *  4.1.2. Attribute Types
 *
 *    Attribute Type definitions are written according to the ABNF:
 *
 *      AttributeTypeDescription = LPAREN WSP
 *          numericoid                   ; object identifier
 *          [ SP &quot;NAME&quot; SP qdescrs ]     ; short names (descriptors)
 *          [ SP &quot;DESC&quot; SP qdstring ]    ; description
 *          [ SP &quot;OBSOLETE&quot; ]            ; not active
 *          [ SP &quot;SUP&quot; SP oid ]          ; supertype
 *          [ SP &quot;EQUALITY&quot; SP oid ]     ; equality matching rule
 *          [ SP &quot;ORDERING&quot; SP oid ]     ; ordering matching rule
 *          [ SP &quot;SUBSTR&quot; SP oid ]       ; substrings matching rule
 *          [ SP &quot;SYNTAX&quot; SP noidlen ]   ; value syntax
 *          [ SP &quot;SINGLE-VALUE&quot; ]        ; single-value
 *          [ SP &quot;COLLECTIVE&quot; ]          ; collective
 *          [ SP &quot;NO-USER-MODIFICATION&quot; ]; not user modifiable
 *          [ SP &quot;USAGE&quot; SP usage ]      ; usage
 *          extensions WSP RPAREN        ; extensions
 *
 *      usage = &quot;userApplications&quot;     / ; user
 *              &quot;directoryOperation&quot;   / ; directory operational
 *              &quot;distributedOperation&quot; / ; DSA-shared operational
 *              &quot;dSAOperation&quot;           ; DSA-specific operational
 *
 *    where:
 *      [numericoid] is object identifier assigned to this attribute type;
 *      NAME [qdescrs] are short names (descriptors) identifying this
 *          attribute type;
 *      DESC [qdstring] is a short descriptive string;
 *      OBSOLETE indicates this attribute type is not active;
 *      SUP oid specifies the direct supertype of this type;
 *      EQUALITY, ORDERING, SUBSTRING provide the oid of the equality,
 *          ordering, and substrings matching rules, respectively;
 *      SYNTAX identifies value syntax by object identifier and may suggest
 *          a minimum upper bound;
 *      COLLECTIVE indicates this attribute type is collective [X.501];
 *      NO-USER-MODIFICATION indicates this attribute type is not user
 *          modifiable;
 *      USAGE indicates the application of this attribute type; and
 *      [extensions] describe extensions.
 *
 *    Each attribute type description must contain at least one of the SUP
 *    or SYNTAX fields.
 *
 *    Usage of userApplications, the default, indicates that attributes of
 *    this type represent user information.  That is, they are user
 *    attributes.
 *
 *    COLLECTIVE requires usage userApplications.  Use of collective
 *    attribute types in LDAP is not discussed in this technical
 *    specification.
 *
 *    A usage of directoryOperation, distributedOperation, or dSAOperation
 *    indicates that attributes of this type represent operational and/or
 *    administrative information.  That is, they are operational attributes.
 *
 *    directoryOperation usage indicates that the attribute of this type is
 *    a directory operational attribute.  distributedOperation usage
 *    indicates that the attribute of this DSA-shared usage operational
 *    attribute.  dSAOperation usage indicates that the attribute of this
 *    type is a DSA-specific operational attribute.
 *
 *    NO-USER-MODIFICATION requires an operational usage.
 *
 *    Note that the [AttributeTypeDescription] does not list the matching
 *    rules which can be used with that attribute type in an extensibleMatch
 *    search filter.  This is done using the 'matchingRuleUse' attribute
 *    described in Section 4.1.4.
 *
 *    This document refines the schema description of X.501 by requiring
 *    that the SYNTAX field in an [AttributeTypeDescription] be a string
 *    representation of an object identifier for the LDAP string syntax
 *    definition with an optional indication of the suggested minimum bound
 *    of a value of this attribute.
 *
 *    A suggested minimum upper bound on the number of characters in a value
 *    with a string-based syntax, or the number of bytes in a value for all
 *    other syntaxes, may be indicated by appending this bound count inside
 *    of curly braces following the syntax's OBJECT IDENTIFIER in an
 *
 *    Attribute Type Description.  This bound is not part of the syntax name
 *    itself.  For instance, &quot;1.3.6.4.1.1466.0{64}&quot; suggests that server
 *    implementations should allow a string to be 64 characters long,
 *    although they may allow longer strings.  Note that a single character
 *    of the Directory String syntax may be encoded in more than one octet
 *    since UTF-8 is a variable-length encoding.
 * </pre>
 *
 * @see <a href="http://www.faqs.org/rfcs/rfc2252.html">RFC 2252 Section 4.2</a>
 * @see <a
 *      href="http://www.ietf.org/internet-drafts/draft-ietf-ldapbis-models-11.txt">
 *      ldapbis [MODELS]</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class MutableAttributeType extends AttributeType
{
    /** The mandatory serialVersionUID */
    public static final long serialVersionUID = 1L;


    /**
     * Creates a AttributeType object using a unique OID.
     *
     * @param oid the OID for this AttributeType
     */
    public MutableAttributeType( String oid )
    {
        super( oid );
    }


    /**
     * Tells if this AttributeType is Single Valued or not
     *
     * @param singleValued True if the AttributeType is single-valued
     */
    public void setSingleValued( boolean singleValued )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.isSingleValued = singleValued;
        }
    }


    /**
     * Tells if this AttributeType can be modified by a user or not
     *
     * @param userModifiable The flag to set
     */
    public void setUserModifiable( boolean userModifiable )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.canUserModify = userModifiable;
        }
    }


    /**
     * Updates the collective flag
     *
     * @param collective The new value to set
     */
    public void updateCollective( boolean collective )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        this.isCollective = collective;
    }


    /**
     * Sets the collective flag
     *
     * @param collective The new value to set
     */
    public void setCollective( boolean collective )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.isCollective = collective;
        }
    }


    /**
     * Sets the AttributeType usage, one of :
     * <ul>
     *   <li>USER_APPLICATIONS</li>
     *   <li>DIRECTORY_OPERATION</li>
     *   <li>DISTRIBUTED_OPERATION</li>
     *   <li>DSA_OPERATION</li>
     * </ul>
     * 
     * @see UsageEnum
     * @param usage The AttributeType usage
     */
    public void setUsage( UsageEnum usage )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.usage = usage;
        }
    }


    /**
     * Updates the AttributeType usage, one of :
     * <ul>
     *   <li>USER_APPLICATIONS</li>
     *   <li>DIRECTORY_OPERATION</li>
     *   <li>DISTRIBUTED_OPERATION</li>
     *   <li>DSA_OPERATION</li>
     * </ul>
     * 
     * @see UsageEnum
     * @param newUsage The AttributeType usage
     */
    public void updateUsage( UsageEnum newUsage )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        this.usage = newUsage;
    }


    /**
     * Sets the length limit of this AttributeType based on its associated
     * syntax.
     *
     * @param length the new length to set
     */
    public void setSyntaxLength( long length )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.syntaxLength = length;
        }
    }


    /**
     * Sets the superior AttributeType OID of this AttributeType
     *
     * @param superiorOid The superior AttributeType OID of this AttributeType
     */
    public void setSuperiorOid( String superiorOid )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.superiorOid = superiorOid;
        }
    }


    /**
     * Sets the superior for this AttributeType
     *
     * @param superior The superior for this AttributeType
     */
    public void setSuperior( MutableAttributeType superior )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.superior = superior;
            this.superiorOid = superior.getOid();
        }
    }


    /**
     * Sets the superior oid for this AttributeType
     *
     * @param newSuperiorOid The superior oid for this AttributeType
     */
    public void setSuperior( String newSuperiorOid )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.superiorOid = newSuperiorOid;
        }
    }


    /**
     * Update the associated Superior AttributeType, even if the SchemaObject is readOnly
     *
     * @param newSuperior The superior for this AttributeType
     */
    public void updateSuperior( MutableAttributeType newSuperior )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        this.superior = newSuperior;
        this.superiorOid = newSuperior.getOid();
    }


    /**
     * Sets the Syntax OID for this AttributeType
     *
     * @param syntaxOid The syntax OID for this AttributeType
     */
    public void setSyntaxOid( String syntaxOid )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.syntaxOid = syntaxOid;
        }
    }


    /**
     * Sets the Syntax for this AttributeType
     *
     * @param syntax The Syntax for this AttributeType
     */
    public void setSyntax( LdapSyntax syntax )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.syntax = syntax;
            this.syntaxOid = syntax.getOid();
        }
    }


    /**
     * Update the associated Syntax, even if the SchemaObject is readOnly
     *
     * @param newSyntax The Syntax for this AttributeType
     */
    public void updateSyntax( LdapSyntax newSyntax )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        this.syntax = newSyntax;
        this.syntaxOid = newSyntax.getOid();
    }


    /**
     * Sets the Equality OID for this AttributeType
     *
     * @param equalityOid The Equality OID for this AttributeType
     */
    public void setEqualityOid( String equalityOid )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.equalityOid = equalityOid;
        }
    }


    /**
     * Sets the Equality MR for this AttributeType
     *
     * @param equality The Equality MR for this AttributeType
     */
    public void setEquality( MatchingRule equality )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.equality = equality;
            this.equalityOid = equality.getOid();
        }
    }


    /**
     * Update the associated Equality MatchingRule, even if the SchemaObject is readOnly
     *
     * @param newEquality The Equality MR for this AttributeType
     */
    public void updateEquality( MatchingRule newEquality )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        this.equality = newEquality;
        this.equalityOid = newEquality.getOid();
    }


    /**
     * Sets the Ordering OID for this AttributeType
     *
     * @param orderingOid The Ordering OID for this AttributeType
     */
    public void setOrderingOid( String orderingOid )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.orderingOid = orderingOid;
        }
    }


    /**
     * Sets the Ordering MR for this AttributeType
     *
     * @param ordering The Ordering MR for this AttributeType
     */
    public void setOrdering( MatchingRule ordering )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.ordering = ordering;
            this.orderingOid = ordering.getOid();
        }
    }


    /**
     * Update the associated Ordering MatchingRule, even if the SchemaObject is readOnly
     *
     * @param newOrdering The Ordering MR for this AttributeType
     */
    public void updateOrdering( MatchingRule newOrdering )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        this.ordering = newOrdering;
        this.orderingOid = newOrdering.getOid();
    }


    /**
     * Sets the Substr OID for this AttributeType
     *
     * @param substrOid The Substr OID for this AttributeType
     */
    public void setSubstringOid( String substrOid )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.substringOid = substrOid;
        }
    }


    /**
     * Sets the Substr MR for this AttributeType
     *
     * @param substring The Substr MR for this AttributeType
     */
    public void setSubstring( MatchingRule substring )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.substring = substring;
            this.substringOid = substring.getOid();
        }
    }


    /**
     * Update the associated Substring MatchingRule, even if the SchemaObject is readOnly
     *
     * @param newSubstring The Substr MR for this AttributeType
     */
    public void updateSubstring( MatchingRule newSubstring )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        this.substring = newSubstring;
        this.substringOid = newSubstring.getOid();
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
        equality = null;
        ordering = null;
        substring = null;
        superior = null;
        syntax = null;
    }
}
