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
import java.util.Map;

import org.apache.directory.api.ldap.model.constants.MetaSchemaConstants;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.util.DateUtils;


/**
 * A factory that generates an entry using the meta schema for schema
 * elements.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AttributesFactory
{
    /**
     * Get a SchemaObject as an Entry
     *
     * @param obj The schema oobject to convert
     * @param schema The schema which this object belongs to
     * @param schemaManager The SchemaManager
     * @return The converted schema object as an Entry
     * @throws LdapException If we can't convert teh schema object
     */
    public Entry getAttributes( SchemaObject obj, Schema schema, SchemaManager schemaManager ) throws LdapException
    {
        if ( obj instanceof LdapSyntax )
        {
            return convert( ( LdapSyntax ) obj, schema, schemaManager );
        }
        else if ( obj instanceof MatchingRule )
        {
            return convert( ( MatchingRule ) obj, schema, schemaManager );
        }
        else if ( obj instanceof AttributeType )
        {
            return convert( ( AttributeType ) obj, schema, schemaManager );
        }
        else if ( obj instanceof ObjectClass )
        {
            return convert( ( ObjectClass ) obj, schema, schemaManager );
        }
        else if ( obj instanceof MatchingRuleUse )
        {
            return convert( ( MatchingRuleUse ) obj, schema, schemaManager );
        }
        else if ( obj instanceof DitStructureRule )
        {
            return convert( ( DitStructureRule ) obj, schema, schemaManager );
        }
        else if ( obj instanceof DitContentRule )
        {
            return convert( ( DitContentRule ) obj, schema, schemaManager );
        }
        else if ( obj instanceof NameForm )
        {
            return convert( ( NameForm ) obj, schema, schemaManager );
        }

        throw new IllegalArgumentException( "nknown SchemaObject type: " + obj.getClass() );
    }


    /**
     * Converts a Schema to an Entry
     * 
     * @param schema The Schema to convert
     * @param schemaManager The SchemaManager
     * @return An Entry containing the converted Schema
     * @throws LdapException If the conversion failed
     */
    public Entry convert( Schema schema, SchemaManager schemaManager ) throws LdapException
    {
        Entry entry = new DefaultEntry( schemaManager );

        entry.put( SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, MetaSchemaConstants.META_SCHEMA_OC );
        entry.put( SchemaConstants.CN_AT, schema.getSchemaName() );
        entry.put( SchemaConstants.CREATORS_NAME_AT, schema.getOwner() );
        entry.put( SchemaConstants.CREATE_TIMESTAMP_AT, DateUtils.getGeneralizedTime() );

        if ( schema.isDisabled() )
        {
            entry.put( MetaSchemaConstants.M_DISABLED_AT, "TRUE" );
        }

        String[] dependencies = schema.getDependencies();

        if ( dependencies != null && dependencies.length > 0 )
        {
            Attribute attr = new DefaultAttribute(
                schemaManager.getAttributeType( MetaSchemaConstants.M_DEPENDENCIES_AT ) );

            for ( String dependency : dependencies )
            {
                attr.add( dependency );
            }

            entry.put( attr );
        }

        return entry;
    }


    /**
     * Convert a SyntaxChecker instance into an Entry
     *
     * @param syntaxChecker The SyntaxChecker to convert
     * @param schema The schema containing this SyntaxChecker
     * @param schemaManager The SchemaManager
     * @return An Entry containing the converted SyntaxChecker
     */
    public Entry convert( SyntaxChecker syntaxChecker, Schema schema, SchemaManager schemaManager )
    {
        Entry entry = new DefaultEntry( schemaManager );

        entry.put( SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, MetaSchemaConstants.META_SYNTAX_CHECKER_OC );
        entry.put( MetaSchemaConstants.M_OID_AT, syntaxChecker.getOid() );
        entry.put( MetaSchemaConstants.M_FQCN_AT, syntaxChecker.getClass().getName() );
        entry.put( SchemaConstants.CREATORS_NAME_AT, schema.getOwner() );
        entry.put( SchemaConstants.CREATE_TIMESTAMP_AT, DateUtils.getGeneralizedTime() );

        return entry;
    }


    /**
     * Convert a Syntax instance into an Entry
     *
     * @param syntax The LdapSytax to convert
     * @param schema The schema containing this Syntax
     * @param schemaManager The SchemaManager
     * @return And entry defining a LdapSyntax
     * @throws LdapException If the conversion failed
     */
    public Entry convert( LdapSyntax syntax, Schema schema, SchemaManager schemaManager ) throws LdapException
    {
        Entry entry = new DefaultEntry( schemaManager );

        entry.put( SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, MetaSchemaConstants.META_SYNTAX_OC );
        entry.put( SchemaConstants.CREATORS_NAME_AT, schema.getOwner() );
        entry.put( SchemaConstants.CREATE_TIMESTAMP_AT, DateUtils.getGeneralizedTime() );
        injectCommon( syntax, entry, schemaManager );

        return entry;
    }


    /**
     * Convert a Normalizer instance into an Entry
     *
     * @param oid The Normalizer's OID
     * @param normalizer The Normalizer to convert
     * @param schema The schema containing this Normalizer
     * @param schemaManager The SchemaManager
     * @return An Entry defining a Normalizer
     */
    public Entry convert( String oid, Normalizer normalizer, Schema schema, SchemaManager schemaManager )
    {
        Entry entry = new DefaultEntry( schemaManager );

        entry.put( SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, MetaSchemaConstants.META_NORMALIZER_OC );
        entry.put( MetaSchemaConstants.M_OID_AT, oid );
        entry.put( MetaSchemaConstants.M_FQCN_AT, normalizer.getClass().getName() );
        entry.put( SchemaConstants.CREATORS_NAME_AT, schema.getOwner() );
        entry.put( SchemaConstants.CREATE_TIMESTAMP_AT, DateUtils.getGeneralizedTime() );
        return entry;
    }


    /**
     * Convert a LdapComparator instance into an Entry
     *
     * @param oid The LdapComparator's OID
     * @param comparator The LdapComparator to convert
     * @param schema The schema containing this Comparator
     * @param schemaManager The SchemaManager
     * @return An Entry defining a LdapComparator
     */
    public Entry convert( String oid, LdapComparator<? super Object> comparator, Schema schema,
        SchemaManager schemaManager )
    {
        Entry entry = new DefaultEntry( schemaManager );

        entry.put( SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, MetaSchemaConstants.META_COMPARATOR_OC );
        entry.put( MetaSchemaConstants.M_OID_AT, oid );
        entry.put( MetaSchemaConstants.M_FQCN_AT, comparator.getClass().getName() );
        entry.put( SchemaConstants.CREATORS_NAME_AT, schema.getOwner() );
        entry.put( SchemaConstants.CREATE_TIMESTAMP_AT, DateUtils.getGeneralizedTime() );
        return entry;
    }


    /**
     * Converts a MatchingRule into an Entry
     * 
     * @param matchingRule The MatchingRule to convert
     * @param schema The schema containing this ObjectClass
     * @param schemaManager The SchemaManager
     * @return The converted MatchingRule
     * @throws LdapException If the conversion failed
     */
    public Entry convert( MatchingRule matchingRule, Schema schema, SchemaManager schemaManager )
        throws LdapException
    {
        Entry entry = new DefaultEntry( schemaManager );

        entry.put( SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, MetaSchemaConstants.META_MATCHING_RULE_OC );
        entry.put( MetaSchemaConstants.M_SYNTAX_AT, matchingRule.getSyntaxOid() );
        entry.put( SchemaConstants.CREATORS_NAME_AT, schema.getOwner() );
        entry.put( SchemaConstants.CREATE_TIMESTAMP_AT, DateUtils.getGeneralizedTime() );
        injectCommon( matchingRule, entry, schemaManager );
        return entry;
    }


    /**
     * Converts a MatchingRuleUse into an Entry
     *
     * @param matchingRuleUse The MatchingRuleUse to convert
     * @param schema The schema containing this MatchingRuleUse
     * @param schemaManager The SchemaManager
     * @return The converted MatchingRuleUse
     */
    public Entry convert( MatchingRuleUse matchingRuleUse, Schema schema, SchemaManager schemaManager )
    {
        Entry entry = new DefaultEntry( schemaManager );

        entry.put( SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, "" );
        entry.put( SchemaConstants.CREATORS_NAME_AT, schema.getOwner() );
        entry.put( SchemaConstants.CREATE_TIMESTAMP_AT, DateUtils.getGeneralizedTime() );
        return entry;
    }


    /**
     * Converts a DitStructureRule into an Entry
     *
     * @param ditStructureRule The DitStructureRule to convert
     * @param schema The schema containing this DitStructureRule
     * @param schemaManager The SchemaManager
     * @return The converted DitStructureRule
     */
    public Entry convert( DitStructureRule ditStructureRule, Schema schema, SchemaManager schemaManager )
    {
        Entry entry = new DefaultEntry( schemaManager );

        entry.put( SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, "" );
        entry.put( SchemaConstants.CREATORS_NAME_AT, schema.getOwner() );
        entry.put( SchemaConstants.CREATE_TIMESTAMP_AT, DateUtils.getGeneralizedTime() );
        return entry;
    }


    /**
     * Converts a DitContentRule into an Entry
     *
     * @param dITContentRule The DitContentRule to convert
     * @param schema The schema containing this DitContentRule
     * @param schemaManager The SchemaManager
     * @return The converted DitContentRule
     */
    public Entry convert( DitContentRule dITContentRule, Schema schema, SchemaManager schemaManager )
    {
        Entry entry = new DefaultEntry( schemaManager );

        entry.put( SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, "" );
        entry.put( SchemaConstants.CREATORS_NAME_AT, schema.getOwner() );
        entry.put( SchemaConstants.CREATE_TIMESTAMP_AT, DateUtils.getGeneralizedTime() );
        return entry;
    }


    /**
     * 
     * Converts a NameForm into an Entry
     *
     * @param nameForm The NameForm to convert
     * @param schema The schema containing this NameForm
     * @param schemaManager The SchemaManager
     * @return The converted NameForm
     */
    public Entry convert( NameForm nameForm, Schema schema, SchemaManager schemaManager )
    {
        Entry entry = new DefaultEntry( schemaManager );

        entry.put( SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, "" );
        entry.put( SchemaConstants.CREATORS_NAME_AT, schema.getOwner() );
        entry.put( SchemaConstants.CREATE_TIMESTAMP_AT, DateUtils.getGeneralizedTime() );
        return entry;
    }


    /**
     * <pre>
     *    objectclass ( 1.3.6.1.4.1.18060.0.4.0.3.3
     *       NAME 'metaAttributeType'
     *       DESC 'meta definition of the AttributeType object'
     *       SUP metaTop
     *       STRUCTURAL
     *       MUST ( m-name $ m-syntax )
     *       MAY ( m-supAttributeType $ m-obsolete $ m-equality $ m-ordering $
     *             m-substr $ m-singleValue $ m-collective $ m-noUserModification $
     *             m-usage $ m-extensionAttributeType )
     *    )
     * </pre>
     * 
     * @param attributeType The AttributeType to convert
     * @param schema The schema containing this AttributeType
     * @param schemaManager The SchemaManager
     * @return The converted AttributeType 
     * @throws LdapException If the conversion failed
     */
    public Entry convert( AttributeType attributeType, Schema schema, SchemaManager schemaManager )
        throws LdapException
    {
        Entry entry = new DefaultEntry( schemaManager );

        entry.put( SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, MetaSchemaConstants.META_ATTRIBUTE_TYPE_OC );
        entry.put( MetaSchemaConstants.M_COLLECTIVE_AT, getBoolean( attributeType.isCollective() ) );
        entry.put( MetaSchemaConstants.M_NO_USER_MODIFICATION_AT, getBoolean( !attributeType.isUserModifiable() ) );
        entry.put( MetaSchemaConstants.M_SINGLE_VALUE_AT, getBoolean( attributeType.isSingleValued() ) );
        entry.put( MetaSchemaConstants.M_USAGE_AT, attributeType.getUsage().toString() );
        entry.put( SchemaConstants.CREATORS_NAME_AT, schema.getOwner() );
        entry.put( SchemaConstants.CREATE_TIMESTAMP_AT, DateUtils.getGeneralizedTime() );

        injectCommon( attributeType, entry, schemaManager );

        String superiorOid = attributeType.getSuperiorOid();

        if ( superiorOid != null )
        {
            entry.put( MetaSchemaConstants.M_SUP_ATTRIBUTE_TYPE_AT, superiorOid );
        }

        if ( attributeType.getEqualityOid() != null )
        {
            entry.put( MetaSchemaConstants.M_EQUALITY_AT, attributeType.getEqualityOid() );
        }

        if ( attributeType.getSubstringOid() != null )
        {
            entry.put( MetaSchemaConstants.M_SUBSTR_AT, attributeType.getSubstringOid() );
        }

        if ( attributeType.getOrderingOid() != null )
        {
            entry.put( MetaSchemaConstants.M_ORDERING_AT, attributeType.getOrderingOid() );
        }

        if ( attributeType.getSyntaxOid() != null )
        {
            entry.put( MetaSchemaConstants.M_SYNTAX_AT, attributeType.getSyntaxOid() );
        }

        return entry;
    }


    /**
     * Creates the attributes of an entry representing an objectClass.
     * 
     * <pre>
     *  objectclass ( 1.3.6.1.4.1.18060.0.4.0.3.2
     *      NAME 'metaObjectClass'
     *      DESC 'meta definition of the objectclass object'
     *      SUP metaTop
     *      STRUCTURAL
     *      MUST m-oid
     *      MAY ( m-name $ m-obsolete $ m-supObjectClass $ m-typeObjectClass $ m-must $
     *            m-may $ m-extensionObjectClass )
     *  )
     * </pre>
     * 
     * @param objectClass the objectClass to produce a meta schema entry for
     * @param schema The schema containing this ObjectClass
     * @param schemaManager The SchemaManager
     * @return the attributes of the metaSchema entry representing the objectClass
     * @throws LdapException If the conversion failed
     */
    public Entry convert( ObjectClass objectClass, Schema schema, SchemaManager schemaManager )
        throws LdapException
    {
        Entry entry = new DefaultEntry( schemaManager );

        entry.put( SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, MetaSchemaConstants.META_OBJECT_CLASS_OC );
        entry.put( MetaSchemaConstants.M_TYPE_OBJECT_CLASS_AT, objectClass.getType().toString() );
        entry.put( SchemaConstants.CREATORS_NAME_AT, schema.getOwner() );
        entry.put( SchemaConstants.CREATE_TIMESTAMP_AT, DateUtils.getGeneralizedTime() );

        injectCommon( objectClass, entry, schemaManager );
        Attribute attr = null;

        // handle the superior objectClasses
        if ( objectClass.getSuperiorOids() != null && !objectClass.getSuperiorOids().isEmpty() )
        {
            if ( schemaManager != null )
            {
                attr = new DefaultAttribute(
                    schemaManager.getAttributeType( MetaSchemaConstants.M_SUP_OBJECT_CLASS_AT ) );
            }
            else
            {
                attr = new DefaultAttribute( MetaSchemaConstants.M_SUP_OBJECT_CLASS_AT );
            }

            for ( String superior : objectClass.getSuperiorOids() )
            {
                attr.add( superior );
            }

            entry.put( attr );
        }

        // add the must list
        if ( objectClass.getMustAttributeTypeOids() != null && !objectClass.getMustAttributeTypeOids().isEmpty() )
        {
            if ( schemaManager != null )
            {
                attr = new DefaultAttribute( schemaManager.getAttributeType( MetaSchemaConstants.M_MUST_AT ) );
            }
            else
            {
                attr = new DefaultAttribute( MetaSchemaConstants.M_MUST_AT );
            }

            for ( String mustOid : objectClass.getMustAttributeTypeOids() )
            {
                attr.add( mustOid );
            }

            entry.put( attr );
        }

        // add the may list
        if ( objectClass.getMayAttributeTypeOids() != null && !objectClass.getMayAttributeTypeOids().isEmpty() )
        {
            if ( schemaManager != null )
            {
                attr = new DefaultAttribute( schemaManager.getAttributeType( MetaSchemaConstants.M_MAY_AT ) );
            }
            else
            {
                attr = new DefaultAttribute( MetaSchemaConstants.M_MAY_AT );
            }

            for ( String mayOid : objectClass.getMayAttributeTypeOids() )
            {
                attr.add( mayOid );
            }

            entry.put( attr );
        }

        return entry;
    }


    private void injectCommon( SchemaObject object, Entry entry, SchemaManager schemaManager )
        throws LdapException
    {
        injectNames( object.getNames(), entry, schemaManager );
        entry.put( MetaSchemaConstants.M_OBSOLETE_AT, getBoolean( object.isObsolete() ) );
        entry.put( MetaSchemaConstants.M_OID_AT, object.getOid() );

        if ( object.getDescription() != null )
        {
            entry.put( MetaSchemaConstants.M_DESCRIPTION_AT, object.getDescription() );
        }

        // The extensions
        Map<String, List<String>> extensions = object.getExtensions();

        if ( extensions != null )
        {
            for ( Map.Entry<String, List<String>> mapEntry : extensions.entrySet() )
            {
                String key = mapEntry.getKey();
                List<String> values = mapEntry.getValue();

                for ( String value : values )
                {
                    entry.add( key, value );
                }
            }
        }
    }


    private void injectNames( List<String> names, Entry entry, SchemaManager schemaManager ) throws LdapException
    {
        if ( ( names == null ) || names.isEmpty() )
        {
            return;
        }

        Attribute attr = null;

        if ( schemaManager != null )
        {
            attr = new DefaultAttribute( schemaManager.getAttributeType( MetaSchemaConstants.M_NAME_AT ) );
        }
        else
        {
            attr = new DefaultAttribute( MetaSchemaConstants.M_NAME_AT );
        }

        for ( String name : names )
        {
            attr.add( name );
        }

        entry.put( attr );
    }


    private String getBoolean( boolean value )
    {
        if ( value )
        {
            return "TRUE";
        }
        else
        {
            return "FALSE";
        }
    }
}
