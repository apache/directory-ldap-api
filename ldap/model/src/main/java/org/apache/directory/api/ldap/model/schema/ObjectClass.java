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


import java.util.ArrayList;
import java.util.List;


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
public class ObjectClass extends AbstractSchemaObject
{
    /** The mandatory serialVersionUID */
    public static final long serialVersionUID = 1L;

    /** The ObjectClass type : ABSTRACT, AUXILIARY or STRUCTURAL */
    protected ObjectClassTypeEnum objectClassType = ObjectClassTypeEnum.STRUCTURAL;

    /** The ObjectClass superior OIDs */
    protected List<String> superiorOids;

    /** The ObjectClass superiors */
    protected List<ObjectClass> superiors;

    /** The list of allowed AttributeType OIDs */
    protected List<String> mayAttributeTypeOids;

    /** The list of allowed AttributeTypes */
    protected List<AttributeType> mayAttributeTypes;

    /** The list of required AttributeType OIDs */
    protected List<String> mustAttributeTypeOids;

    /** The list of required AttributeTypes */
    protected List<AttributeType> mustAttributeTypes;


    /**
     * Creates a new instance of MatchingRuleUseDescription
     * @param oid the OID for this objectClass
     */
    public ObjectClass( String oid )
    {
        super( SchemaObjectType.OBJECT_CLASS, oid );

        mayAttributeTypeOids = new ArrayList<>();
        mustAttributeTypeOids = new ArrayList<>();
        superiorOids = new ArrayList<>();

        mayAttributeTypes = new ArrayList<>();
        mustAttributeTypes = new ArrayList<>();
        superiors = new ArrayList<>();
        objectClassType = ObjectClassTypeEnum.STRUCTURAL;
    }


    /**
     * @return the mayAttributeTypeOids
     */
    public List<String> getMayAttributeTypeOids()
    {
        return mayAttributeTypeOids;
    }


    /**
     * @return the mayAttributeTypes
     */
    public List<AttributeType> getMayAttributeTypes()
    {
        return mayAttributeTypes;
    }


    /**
     * @return the mustAttributeTypeOids
     */
    public List<String> getMustAttributeTypeOids()
    {
        return mustAttributeTypeOids;
    }


    /**
     * @return the mustAttributeTypes
     */
    public List<AttributeType> getMustAttributeTypes()
    {
        return mustAttributeTypes;
    }


    /**
     * Gets the superclasses of this ObjectClass.
     *
     * @return the superclasses
     */
    public List<ObjectClass> getSuperiors()
    {
        return superiors;
    }


    /**
     * Gets the superclasses OIDsof this ObjectClass.
     *
     * @return the superclasses OIDs
     */
    public List<String> getSuperiorOids()
    {
        return superiorOids;
    }


    /**
     * Gets the type of this ObjectClass as a type safe enum.
     *
     * @return the ObjectClass type as an enum
     */
    public ObjectClassTypeEnum getType()
    {
        return objectClassType;
    }


    /**
     * Tells if the current ObjectClass is STRUCTURAL
     *
     * @return <code>true</code> if the ObjectClass is STRUCTURAL
     */
    public boolean isStructural()
    {
        return objectClassType == ObjectClassTypeEnum.STRUCTURAL;
    }


    /**
     * Tells if the current ObjectClass is ABSTRACT
     *
     * @return <code>true</code> if the ObjectClass is ABSTRACT
     */
    public boolean isAbstract()
    {
        return objectClassType == ObjectClassTypeEnum.ABSTRACT;
    }


    /**
     * Tells if the current ObjectClass is AUXILIARY
     *
     * @return <code>true</code> if the ObjectClass is AUXILIARY
     */
    public boolean isAuxiliary()
    {
        return objectClassType == ObjectClassTypeEnum.AUXILIARY;
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
     * Copy an ObjectClass
     */
    @Override
    public ObjectClass copy()
    {
        ObjectClass copy = new ObjectClass( oid );

        // Copy the SchemaObject common data
        copy.copy( this );

        // Copy the ObjectClass type
        copy.objectClassType = objectClassType;

        // Copy the Superiors ObjectClasses OIDs
        copy.superiorOids = new ArrayList<>();

        for ( String oid : superiorOids )
        {
            copy.superiorOids.add( oid );
        }

        // Copy the Superiors ObjectClasses ( will be empty )
        copy.superiors = new ArrayList<>();

        // Copy the MAY AttributeTypes OIDs
        copy.mayAttributeTypeOids = new ArrayList<>();

        for ( String oid : mayAttributeTypeOids )
        {
            copy.mayAttributeTypeOids.add( oid );
        }

        // Copy the MAY AttributeTypes ( will be empty )
        copy.mayAttributeTypes = new ArrayList<>();

        // Copy the MUST AttributeTypes OIDs
        copy.mustAttributeTypeOids = new ArrayList<>();

        for ( String oid : mustAttributeTypeOids )
        {
            copy.mustAttributeTypeOids.add( oid );
        }

        // Copy the MUST AttributeTypes ( will be empty )
        copy.mustAttributeTypes = new ArrayList<>();

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

        if ( !( o instanceof ObjectClass ) )
        {
            return false;
        }

        ObjectClass that = ( ObjectClass ) o;

        // The ObjectClassType
        if ( objectClassType != that.objectClassType )
        {
            return false;
        }

        // The Superiors OIDs
        if ( superiorOids.size() != that.superiorOids.size() )
        {
            return false;
        }

        // One way
        for ( String oid : superiorOids )
        {
            if ( !that.superiorOids.contains( oid ) )
            {
                return false;
            }
        }

        // The other way
        for ( String oid : that.superiorOids )
        {
            if ( !superiorOids.contains( oid ) )
            {
                return false;
            }
        }

        // The Superiors
        if ( superiors.size() != that.superiors.size() )
        {
            return false;
        }

        // One way
        for ( ObjectClass oid : superiors )
        {
            if ( !that.superiors.contains( oid ) )
            {
                return false;
            }
        }

        // The other way
        for ( ObjectClass oid : that.superiors )
        {
            if ( !superiors.contains( oid ) )
            {
                return false;
            }
        }

        // The MAY OIDs
        if ( mayAttributeTypeOids.size() != that.mayAttributeTypeOids.size() )
        {
            return false;
        }

        // One way
        for ( String oid : mayAttributeTypeOids )
        {
            if ( !that.mayAttributeTypeOids.contains( oid ) )
            {
                return false;
            }
        }

        // The other way
        for ( String oid : that.mayAttributeTypeOids )
        {
            if ( !mayAttributeTypeOids.contains( oid ) )
            {
                return false;
            }
        }

        // The MAY
        if ( mayAttributeTypes.size() != that.mayAttributeTypes.size() )
        {
            return false;
        }

        // One way
        for ( AttributeType oid : mayAttributeTypes )
        {
            if ( !that.mayAttributeTypes.contains( oid ) )
            {
                return false;
            }
        }

        // The other way
        for ( AttributeType oid : that.mayAttributeTypes )
        {
            if ( !mayAttributeTypes.contains( oid ) )
            {
                return false;
            }
        }

        // The MUST OIDs
        if ( mustAttributeTypeOids.size() != that.mustAttributeTypeOids.size() )
        {
            return false;
        }

        // One way
        for ( String oid : mustAttributeTypeOids )
        {
            if ( !that.mustAttributeTypeOids.contains( oid ) )
            {
                return false;
            }
        }

        // The other way
        for ( String oid : that.mustAttributeTypeOids )
        {
            if ( !mustAttributeTypeOids.contains( oid ) )
            {
                return false;
            }
        }

        // The MUST
        if ( mustAttributeTypes.size() != that.mustAttributeTypes.size() )
        {
            return false;
        }

        // One way
        for ( AttributeType oid : mustAttributeTypes )
        {
            if ( !that.mustAttributeTypes.contains( oid ) )
            {
                return false;
            }
        }

        // The other way
        for ( AttributeType oid : that.mustAttributeTypes )
        {
            if ( !mustAttributeTypes.contains( oid ) )
            {
                return false;
            }
        }

        return true;
    }
}