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
import java.util.Collections;
import java.util.List;

import org.apache.directory.api.i18n.I18n;


/**
 * A nameForm description. NameForms define the relationship between a
 * STRUCTURAL objectClass definition and the attributeTypes allowed to be used
 * for the naming of an Entry of that objectClass: it defines which attributes
 * can be used for the Rdn.
 * <p>
 * According to ldapbis [MODELS]:
 * </p>
 * 
 * <pre>
 *  4.1.7.2. Name Forms
 * 
 *   A name form &quot;specifies a permissible Rdn for entries of a particular
 *   structural object class.  A name form identifies a named object
 *   class and one or more attribute types to be used for naming (i.e.
 *   for the Rdn).  Name forms are primitive pieces of specification
 *   used in the definition of DIT structure rules&quot; [X.501].
 * 
 *   Each name form indicates the structural object class to be named,
 *   a set of required attribute types, and a set of allowed attributes
 *   types.  A particular attribute type cannot be listed in both sets.
 * 
 *   Entries governed by the form must be named using a value from each
 *   required attribute type and zero or more values from the allowed
 *   attribute types.
 * 
 *   Each name form is identified by an object identifier (OID) and,
 *   optionally, one or more short names (descriptors).
 * 
 *   Name form descriptions are written according to the ABNF:
 * 
 *     NameFormDescription = LPAREN WSP
 *         numericoid                ; object identifier
 *         [ SP &quot;NAME&quot; SP qdescrs ]  ; short names (descriptors)
 *         [ SP &quot;DESC&quot; SP qdstring ] ;String description
 *         [ SP &quot;OBSOLETE&quot; ]         ; not active
 *         SP &quot;OC&quot; SP oid            ; structural object class
 *         SP &quot;MUST&quot; SP oids         ; attribute types
 *         [ SP &quot;MAY&quot; SP oids ]      ; attribute types
 *         extensions WSP RPAREN     ; extensions
 * 
 *   where:
 * 
 *     [numericoid] is object identifier which identifies this name form;
 *     NAME [qdescrs] are short names (descriptors) identifying this name
 *         form;
 *     DESC [qdstring] is a short descriptive string;
 *     OBSOLETE indicates this name form is not active;
 *     OC identifies the structural object class this rule applies to,
 *     MUST and MAY specify the sets of required and allowed, respectively,
 *         naming attributes for this name form; and
 *     [extensions] describe extensions.
 * 
 *   All attribute types in the required (&quot;MUST&quot;) and allowed (&quot;MAY&quot;) lists
 *   shall be different.
 * </pre>
 * 
 * @see <a href="http://www.faqs.org/rfcs/rfc225String2.html">RFC2252 Section 6.22</a>
 * @see <a
 *      href="http://www.ietf.org/internet-drafts/draft-ietf-ldapbis-models-11.txt">ldapbis
 *      [MODELS]</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class NameForm extends AbstractSchemaObject
{
    /** Declares the Serial Version Uid */
    public static final long serialVersionUID = 1L;

    /** The structural object class OID this rule applies to */
    private String structuralObjectClassOid;

    /** The structural object class this rule applies to */
    private ObjectClass structuralObjectClass;

    /** The set of required attribute OIDs for this name form */
    private List<String> mustAttributeTypeOids;

    /** The set of required AttributeTypes for this name form */
    private List<AttributeType> mustAttributeTypes;

    /** The set of allowed attribute OIDs for this name form */
    private List<String> mayAttributeTypeOids;

    /** The set of allowed AttributeTypes for this name form */
    private List<AttributeType> mayAttributeTypes;

    /**
     * Creates a new instance of MatchingRule.
     *
     * @param oid The MatchingRule OID
     */
    public NameForm( String oid )
    {
        super( SchemaObjectType.NAME_FORM, oid );

        mustAttributeTypeOids = new ArrayList<>();
        mayAttributeTypeOids = new ArrayList<>();

        mustAttributeTypes = new ArrayList<>();
        mayAttributeTypes = new ArrayList<>();
    }


    /**
     * Gets the STRUCTURAL ObjectClass this name form specifies naming
     * attributes for.
     * 
     * @return the ObjectClass's oid this NameForm is for
     */
    public String getStructuralObjectClassOid()
    {
        return structuralObjectClassOid;
    }


    /**
     * Gets the STRUCTURAL ObjectClass this name form specifies naming
     * attributes for.
     * 
     * @return the ObjectClass this NameForm is for
     */
    public ObjectClass getStructuralObjectClass()
    {
        return structuralObjectClass;
    }


    /**
     * Sets the structural object class this rule applies to
     * 
     * @param structuralObjectClassOid the structural object class to set
     */
    public void setStructuralObjectClassOid( String structuralObjectClassOid )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.structuralObjectClassOid = structuralObjectClassOid;
    }


    /**
     * Sets the structural object class this rule applies to
     * 
     * @param structuralObjectClass the structural object class to set
     */
    public void setStructuralObjectClass( ObjectClass structuralObjectClass )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.structuralObjectClass = structuralObjectClass;
        this.structuralObjectClassOid = structuralObjectClass.getOid();
    }


    /**
     * Gets all the AttributeTypes OIDs of the attributes this NameForm specifies as
     * having to be used in the given objectClass for naming: as part of the
     * Rdn.
     * 
     * @return the AttributeTypes OIDs of the must use attributes
     */
    public List<String> getMustAttributeTypeOids()
    {
        return Collections.unmodifiableList( mustAttributeTypeOids );
    }


    /**
     * Gets all the AttributeTypes of the attributes this NameForm specifies as
     * having to be used in the given objectClass for naming: as part of the
     * Rdn.
     * 
     * @return the AttributeTypes of the must use attributes
     */
    public List<AttributeType> getMustAttributeTypes()
    {
        return Collections.unmodifiableList( mustAttributeTypes );
    }


    /**
     * Sets the list of required AttributeTypes OIDs
     *
     * @param mustAttributeTypeOids the list of required AttributeTypes OIDs
     */
    public void setMustAttributeTypeOids( List<String> mustAttributeTypeOids )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.mustAttributeTypeOids = mustAttributeTypeOids;
    }


    /**
     * Sets the list of required AttributeTypes
     *
     * @param mustAttributeTypes the list of required AttributeTypes
     */
    public void setMustAttributeTypes( List<AttributeType> mustAttributeTypes )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.mustAttributeTypes = mustAttributeTypes;

        // update the OIDS now
        mustAttributeTypeOids.clear();

        for ( AttributeType may : mustAttributeTypes )
        {
            mustAttributeTypeOids.add( may.getOid() );
        }
    }


    /**
     * Add a required AttributeType OID
     *
     * @param oid The attributeType OID
     */
    public void addMustAttributeTypeOids( String oid )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        mustAttributeTypeOids.add( oid );
    }


    /**
     * Add a required AttributeType
     *
     * @param attributeType The attributeType
     */
    public void addMustAttributeTypes( AttributeType attributeType )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        if ( !mustAttributeTypeOids.contains( attributeType.getOid() ) )
        {
            mustAttributeTypes.add( attributeType );
            mustAttributeTypeOids.add( attributeType.getOid() );
        }
    }


    /**
     * Gets all the AttributeTypes OIDs of the attribute this NameForm specifies as
     * being usable without requirement in the given objectClass for naming: as
     * part of the Rdn.
     * 
     * @return the AttributeTypes OIDs of the may use attributes
     */
    public List<String> getMayAttributeTypeOids()
    {
        return Collections.unmodifiableList( mayAttributeTypeOids );
    }


    /**
     * Gets all the AttributeTypes of the attribute this NameForm specifies as
     * being useable without requirement in the given objectClass for naming: as
     * part of the Rdn.
     * 
     * @return the AttributeTypes of the may use attributes
     */
    public List<AttributeType> getMayAttributeTypes()
    {
        return Collections.unmodifiableList( mayAttributeTypes );
    }


    /**
     * Sets the list of allowed AttributeTypes
     *
     * @param mayAttributeTypeOids the list of allowed AttributeTypes
     */
    public void setMayAttributeTypeOids( List<String> mayAttributeTypeOids )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.mayAttributeTypeOids = mayAttributeTypeOids;
    }


    /**
     * Sets the list of allowed AttributeTypes
     *
     * @param mayAttributeTypes the list of allowed AttributeTypes
     */
    public void setMayAttributeTypes( List<AttributeType> mayAttributeTypes )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.mayAttributeTypes = mayAttributeTypes;

        // update the OIDS now
        mayAttributeTypeOids.clear();

        for ( AttributeType may : mayAttributeTypes )
        {
            mayAttributeTypeOids.add( may.getOid() );
        }
    }


    /**
     * Add an allowed AttributeType
     *
     * @param oid The attributeType oid
     */
    public void addMayAttributeTypeOids( String oid )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        mayAttributeTypeOids.add( oid );
    }


    /**
     * Add an allowed AttributeType
     *
     * @param attributeType The attributeType
     */
    public void addMayAttributeTypes( AttributeType attributeType )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        if ( !mayAttributeTypeOids.contains( attributeType.getOid() ) )
        {
            mayAttributeTypes.add( attributeType );
            mayAttributeTypeOids.add( attributeType.getOid() );
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
     * Copy a NameForm
     */
    @Override
    public NameForm copy()
    {
        NameForm copy = new NameForm( oid );

        // Copy the SchemaObject common data
        copy.copy( this );

        // Copy the MAY AttributeTypes OIDs
        copy.mayAttributeTypeOids = new ArrayList<>();

        for ( String oid : mayAttributeTypeOids )
        {
            copy.mayAttributeTypeOids.add( oid );
        }

        // Copy the MAY AttributeTypes (will be empty)
        copy.mayAttributeTypes = new ArrayList<>();

        // Copy the MUST AttributeTypes OIDs
        copy.mustAttributeTypeOids = new ArrayList<>();

        for ( String oid : mustAttributeTypeOids )
        {
            copy.mustAttributeTypeOids.add( oid );
        }

        // Copy the MUST AttributeTypes ( will be empty )
        copy.mustAttributeTypes = new ArrayList<>();

        // Copy the Structural ObjectClass OID
        copy.structuralObjectClassOid = structuralObjectClassOid;

        // All the references to other Registries object are set to null.
        copy.structuralObjectClass = null;

        return copy;
    }

    
    /**
     * @see Object#equals(Object)
     */
    @Override
    public int hashCode()
    {
        int hash = h;
        
        // TODO: complete this method
     
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

        if ( !( o instanceof NameForm ) )
        {
            return false;
        }

        @SuppressWarnings("unused")
        NameForm that = ( NameForm ) o;

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
        mayAttributeTypes.clear();
        mayAttributeTypeOids.clear();
        mustAttributeTypes.clear();
        mustAttributeTypeOids.clear();
        structuralObjectClass = null;
    }
}
