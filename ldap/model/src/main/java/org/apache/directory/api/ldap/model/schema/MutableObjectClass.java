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


import java.util.List;

import org.apache.directory.api.i18n.I18n;


/**
 * An objectClass definition.
 * <p>
 * According to ldapbis [MODELS]:
 * </p>
 *
 * <pre>
 *  Object Class definitions are written according to the ABNF:
 *
 *    ObjectClassDescription = LPAREN WSP
 *        numericoid                ; object identifier
 *        [ SP &quot;NAME&quot; SP qdescrs ]  ; short names (descriptors)
 *        [ SP &quot;DESC&quot; SP qdstring ] ; description
 *        [ SP &quot;OBSOLETE&quot; ]         ; not active
 *        [ SP &quot;SUP&quot; SP oids ]      ; superior object classes
 *        [ SP kind ]               ; kind of class
 *        [ SP &quot;MUST&quot; SP oids ]     ; attribute types
 *        [ SP &quot;MAY&quot; SP oids ]      ; attribute types
 *        extensions WSP RPAREN
 *
 *     kind = &quot;ABSTRACT&quot; / &quot;STRUCTURAL&quot; / &quot;AUXILIARY&quot;
 *
 *   where:
 *     [numericoid] is object identifier assigned to this object class;
 *     NAME [qdescrs] are short names (descriptors) identifying this object
 *         class;
 *     DESC [qdstring] is a short descriptive string;
 *     OBSOLETE indicates this object class is not active;
 *     SUP [oids] specifies the direct superclasses of this object class;
 *     the kind of object class is indicated by one of ABSTRACT,
 *         STRUCTURAL, or AUXILIARY, default is STRUCTURAL;
 *     MUST and MAY specify the sets of required and allowed attribute
 *         types, respectively; and
 *    [extensions] describe extensions.
 * </pre>
 *
 * @see <a href="http://www.faqs.org/rfcs/rfc2252.html">RFC2252 Section 4.4</a>
 * @see <a
 *      href="http://www.ietf.org/internet-drafts/draft-ietf-ldapbis-models-11.txt">ldapbis
 *      [MODELS]</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class MutableObjectClass extends ObjectClass
{
    /** The mandatory serialVersionUID */
    public static final long serialVersionUID = 1L;


    /**
     * Creates a new instance of MatchingRuleUseDescription
     * @param oid the OID for this objectClass
     */
    public MutableObjectClass( String oid )
    {
        super( oid );
    }


    /**
     * Add some allowed AttributeType
     *
     * @param oids The attributeType oids
     */
    public void addMayAttributeTypeOids( String... oids )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            for ( String oid : oids )
            {
                mayAttributeTypeOids.add( oid );
            }
        }
    }


    /**
     * Add some allowed AttributeTypes
     *
     * @param attributeTypes The attributeTypes
     */
    public void addMayAttributeTypes( AttributeType... attributeTypes )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            for ( AttributeType attributeType : attributeTypes )
            {
                if ( !mayAttributeTypeOids.contains( attributeType.getOid() ) )
                {
                    mayAttributeTypes.add( attributeType );
                    mayAttributeTypeOids.add( attributeType.getOid() );
                }
            }
        }
    }


    /**
     * @param mayAttributeTypeOids the mayAttributeTypeOids to set
     */
    public void setMayAttributeTypeOids( List<String> mayAttributeTypeOids )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.mayAttributeTypeOids = mayAttributeTypeOids;
        }
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
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.mayAttributeTypes = mayAttributeTypes;

            // update the OIDS now
            mayAttributeTypeOids.clear();

            for ( AttributeType may : mayAttributeTypes )
            {
                mayAttributeTypeOids.add( may.getOid() );
            }
        }
    }


    /**
     * Update the associated MAY AttributeType, even if the SchemaObject is readOnly
     *
     * @param mayAttributeTypes the list of allowed AttributeTypes
     */
    public void updateMayAttributeTypes( List<AttributeType> mayAttributeTypes )
    {
        this.mayAttributeTypes.clear();
        this.mayAttributeTypes.addAll( mayAttributeTypes );

        // update the OIDS now
        mayAttributeTypeOids.clear();

        for ( AttributeType may : mayAttributeTypes )
        {
            mayAttributeTypeOids.add( may.getOid() );
        }
    }


    /**
     * Add some required AttributeType OIDs
     *
     * @param oids The attributeType OIDs
     */
    public void addMustAttributeTypeOids( String... oids )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            for ( String oid : oids )
            {
                mustAttributeTypeOids.add( oid );
            }
        }
    }


    /**
     * Add some required AttributeTypes
     *
     * @param attributeTypes The attributeTypse
     */
    public void addMustAttributeTypes( AttributeType... attributeTypes )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            for ( AttributeType attributeType : attributeTypes )
            {
                if ( !mustAttributeTypeOids.contains( attributeType.getOid() ) )
                {
                    mustAttributeTypes.add( attributeType );
                    mustAttributeTypeOids.add( attributeType.getOid() );
                }
            }
        }
    }


    /**
     * @param mustAttributeTypeOids the mustAttributeTypeOids to set
     */
    public void setMustAttributeTypeOids( List<String> mustAttributeTypeOids )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.mustAttributeTypeOids = mustAttributeTypeOids;
        }
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
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.mustAttributeTypes = mustAttributeTypes;

            // update the OIDS now
            mustAttributeTypeOids.clear();

            for ( AttributeType may : mustAttributeTypes )
            {
                mustAttributeTypeOids.add( may.getOid() );
            }
        }
    }


    /**
     * Update the associated MUST AttributeType, even if the SchemaObject is readOnly
     *
     * @param mustAttributeTypes the list of allowed AttributeTypes
     */
    public void updateMustAttributeTypes( List<AttributeType> mustAttributeTypes )
    {
        this.mustAttributeTypes.clear();
        this.mustAttributeTypes.addAll( mustAttributeTypes );

        // update the OIDS now
        mustAttributeTypeOids.clear();

        for ( AttributeType must : mustAttributeTypes )
        {
            mustAttributeTypeOids.add( must.getOid() );
        }
    }


    /**
     * Add some superior ObjectClass OIDs
     *
     * @param oids The superior ObjectClass OIDs
     */
    public void addSuperiorOids( String... oids )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            for ( String oid : oids )
            {
                if ( !superiorOids.contains( oid ) )
                {
                    superiorOids.add( oid );
                }
            }
        }
    }


    /**
     * Add some superior ObjectClasses
     *
     * @param objectClasses The superior ObjectClasses
     */
    public void addSuperior( MutableObjectClass... objectClasses )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            for ( MutableObjectClass objectClass : objectClasses )
            {
                if ( !superiorOids.contains( objectClass.getOid() ) )
                {
                    superiorOids.add( objectClass.getOid() );
                    superiors.add( objectClass );
                }
            }
        }
    }


    /**
     * Sets the superior object classes
     *
     * @param superiors the object classes to set
     */
    public void setSuperiors( List<ObjectClass> superiors )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.superiors = superiors;

            // update the OIDS now
            superiorOids.clear();

            for ( ObjectClass oc : superiors )
            {
                superiorOids.add( oc.getOid() );
            }
        }
    }


    /**
     * Update the associated SUPERIORS ObjectClasses, even if the SchemaObject is readOnly
     *
     * @param superiors the object classes to set
     */
    public void updateSuperiors( List<ObjectClass> superiors )
    {
        this.superiors.clear();
        this.superiors.addAll( superiors );

        // update the OIDS now
        superiorOids.clear();

        for ( ObjectClass oc : superiors )
        {
            superiorOids.add( oc.getOid() );
        }
    }


    /**
     * Sets the superior object class OIDs
     *
     * @param superiorOids the object class OIDs to set
     */
    public void setSuperiorOids( List<String> superiorOids )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.superiorOids = superiorOids;
        }
    }


    /**
     * Set the ObjectClass type, one of ABSTRACT, AUXILIARY or STRUCTURAL.
     *
     * @param objectClassType The ObjectClassType value
     */
    public void setType( ObjectClassTypeEnum objectClassType )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.objectClassType = objectClassType;
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
        mayAttributeTypes.clear();
        mayAttributeTypeOids.clear();
        mustAttributeTypes.clear();
        mustAttributeTypeOids.clear();
        superiors.clear();
        superiorOids.clear();
    }
}