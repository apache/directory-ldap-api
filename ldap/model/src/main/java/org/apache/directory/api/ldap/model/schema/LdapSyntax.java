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


import java.util.List;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.MetaSchemaConstants;


/**
 * A syntax definition. Each attribute stored in a directory has a defined
 * syntax (i.e. data type) which constrains the structure and format of its
 * values. The description of each syntax specifies how attribute or assertion
 * values conforming to the syntax are normally represented when transferred in
 * LDAP operations. This representation is referred to as the LDAP-specific
 * encoding to distinguish it from other methods of encoding attribute values.
 * <p>
 * According to ldapbis [MODELS]:
 * </p>
 * 
 * <pre>
 *  4.1.5. LDAP Syntaxes
 * 
 *    LDAP Syntaxes of (attribute and assertion) values are described in
 *    terms of ASN.1 [X.680] and, optionally, have an octet string encoding
 *    known as the LDAP-specific encoding.  Commonly, the LDAP-specific
 *    encoding is constrained to string of Universal Character Set (UCS)
 *    [ISO10646] characters in UTF-8 [UTF-8] form.
 * 
 *    Each LDAP syntax is identified by an object identifier (OID).
 * 
 *    LDAP syntax definitions are written according to the ABNF:
 * 
 *      SyntaxDescription = LPAREN WSP
 *          numericoid                ; object identifier
 *          [ SP &quot;DESC&quot; SP qdstring ] ; description
 *          extensions WSP RPAREN     ; extensions
 * 
 *    where:
 *      [numericoid] is object identifier assigned to this LDAP syntax;
 *      DESC [qdstring] is a short descriptive string; and
 *      [extensions] describe extensions.
 * </pre>
 * 
 * @see <a href="http://www.faqs.org/rfcs/rfc2252.html"> RFC2252 Section 4.3.3</a>
 * @see <a href=
 *      "http://www.ietf.org/internet-drafts/draft-ietf-ldapbis-models-09.txt">
 *      ldapbis [MODELS]</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapSyntax extends AbstractSchemaObject
{
    /** Declares the Serial Version Uid */
    public static final long serialVersionUID = 1L;

    /** the human readable flag */
    protected boolean isHumanReadable = false;

    /** A flag set to true if the Syntax has a X-NOT-HUMAN-READABLE extension */
    private boolean hasHumanReadableFlag = false;

    /** The associated SyntaxChecker */
    protected SyntaxChecker syntaxChecker;

    /**
     * Creates a Syntax object using a unique OID.
     * 
     * @param oid the OID for this Syntax
     */
    public LdapSyntax( String oid )
    {
        super( SchemaObjectType.LDAP_SYNTAX, oid );
    }


    /**
     * Creates a Syntax object using a unique OID.
     *
     * @param oid the OID for this syntax
     * @param description the description for this syntax
     */
    public LdapSyntax( String oid, String description )
    {
        super( SchemaObjectType.LDAP_SYNTAX, oid );
        this.description = description;
        this.hasHumanReadableFlag = false;
        rehash();
    }


    /**
     * Creates a Syntax object using a unique OID.
     *
     * @param oid the OID for this syntax
     * @param description the description for this syntax
     * @param isHumanReadable true if this syntax is human readable
     */
    public LdapSyntax( String oid, String description, boolean isHumanReadable )
    {
        super( SchemaObjectType.LDAP_SYNTAX, oid );
        this.description = description;
        this.isHumanReadable = isHumanReadable;
        this.hasHumanReadableFlag = true;
        rehash();
    }


    /**
     * Gets whether or not the Syntax is human readable.
     * 
     * @return true if the syntax can be interpreted by humans, false otherwise
     */
    public boolean isHumanReadable()
    {
        if ( hasHumanReadableFlag )
        {
            return isHumanReadable;
        }
        else
        {
            List<String> values = getExtension( MetaSchemaConstants.X_NOT_HUMAN_READABLE_AT );

            if ( ( values == null ) || values.isEmpty() )
            {
                // Default to String if the flag is not set
                return true;
            }
            else
            {
                String value = values.get( 0 );
                hasHumanReadableFlag = true;

                if ( "FALSE".equalsIgnoreCase( value ) )
                {
                    isHumanReadable = true;
                    return true;
                }
                else
                {
                    isHumanReadable = false;
                    return false;
                }
            }
        }
    }


    /**
     * Sets the human readable flag value.
     * 
     * @param humanReadable the human readable flag value to set
     */
    public void setHumanReadable( boolean humanReadable )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.isHumanReadable = humanReadable;
        this.hasHumanReadableFlag = true;
        rehash();
    }


    /**
     * Gets the SyntaxChecker used to validate values in accordance with this
     * Syntax.
     * 
     * @return the SyntaxChecker
     */
    public SyntaxChecker getSyntaxChecker()
    {
        return syntaxChecker;
    }


    /**
     * Sets the associated SyntaxChecker
     *
     * @param syntaxChecker The associated SyntaxChecker
     */
    public void setSyntaxChecker( SyntaxChecker syntaxChecker )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.syntaxChecker = syntaxChecker;
        rehash();
    }


    /**
     * Update the associated SyntaxChecker, even if the SchemaObject is readOnly
     *
     * @param newSyntaxChecker The associated SyntaxChecker
     */
    public void updateSyntaxChecker( SyntaxChecker newSyntaxChecker )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.syntaxChecker = newSyntaxChecker;
        rehash();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return SchemaObjectRenderer.OPEN_LDAP_SCHEMA_RENDERER.render( this );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapSyntax copy()
    {
        LdapSyntax copy = new LdapSyntax( oid );

        // Copy the SchemaObject common data
        copy.copy( this );

        // Copy the HR flag
        copy.isHumanReadable = isHumanReadable;

        // Copy the HR presence flag
        copy.hasHumanReadableFlag = hasHumanReadableFlag;

        // All the references to other Registries object are set to null.
        copy.syntaxChecker = null;
        
        copy.rehash();

        return copy;
    }

    
    /**
     * @see Object#equals(Object)
     */
    @Override
    public void rehash()
    {
        int hash = h;
        
        hash = hash * 17 + ( isHumanReadable ? 1 : 0 );
        
        if ( syntaxChecker != null )
        {
            hash = hash * 17 + syntaxChecker.hashCode();
        }
        
        h = hash;
    }
    

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals( Object o )
    {
        if ( !super.equals( o ) )
        {
            return false;
        }

        if ( !( o instanceof LdapSyntax ) )
        {
            return false;
        }

        LdapSyntax that = ( LdapSyntax ) o;

        // IsHR
        if ( isHumanReadable != that.isHumanReadable )
        {
            return false;
        }

        // Check the SyntaxChecker (not a equals)
        if ( syntaxChecker != null )
        {
            if ( that.syntaxChecker == null )
            {
                return false;
            }

            return syntaxChecker.getOid().equals( that.syntaxChecker.getOid() );
        }
        else
        {
            return that.syntaxChecker == null;
        }
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
        syntaxChecker = null;
        rehash();
    }
}
