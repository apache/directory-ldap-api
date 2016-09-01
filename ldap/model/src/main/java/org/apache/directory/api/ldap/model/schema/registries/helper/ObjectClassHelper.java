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
package org.apache.directory.api.ldap.model.schema.registries.helper;

import java.util.List;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaExceptionCodes;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.apache.directory.api.ldap.model.schema.ObjectClassTypeEnum;
import org.apache.directory.api.ldap.model.schema.registries.AttributeTypeRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ObjectClassRegistry;
import org.apache.directory.api.ldap.model.schema.registries.Registries;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An helper class used to store all the methods associated with an ObjectClass
 * in relation with the Registries and SchemaManager.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class ObjectClassHelper
{
    private ObjectClassHelper()
    {
    }

    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( ObjectClassHelper.class );

    /**
     * Inject the ObjectClass into the registries, updating the references to
     * other SchemaObject
     *
     * @param objectClass The ObjectClass to add to the Registries
     * @param errors The errors we got while adding the ObjectClass to the Registries
     * @param registries The Registries
     * @throws LdapException on failure
     */
    public static void addToRegistries( ObjectClass objectClass, List<Throwable> errors, Registries registries ) throws LdapException
    {
        if ( registries != null )
        {
            try
            {
                objectClass.unlock();
                
                // The superiors
                buildSuperiors( objectClass, errors, registries );
    
                // The MAY AttributeTypes
                buildMay( objectClass, errors, registries );
    
                // The MUST AttributeTypes
                buildMust( objectClass, errors, registries );
    
                /**
                 * Add the OC references (using and usedBy) :
                 * OC -> AT (MAY and MUST)
                 * OC -> OC (SUPERIORS)
                 */
                for ( AttributeType mayAttributeType : objectClass.getMayAttributeTypes() )
                {
                    registries.addReference( objectClass, mayAttributeType );
                }
    
                for ( AttributeType mustAttributeType : objectClass.getMustAttributeTypes() )
                {
                    registries.addReference( objectClass, mustAttributeType );
                }
    
                for ( ObjectClass superiorObjectClass : objectClass.getSuperiors() )
                {
                    registries.addReference( objectClass, superiorObjectClass );
                }
            }
            finally
            {
                objectClass.lock();
            }
        }
    }


    /**
     * Build the references to this ObjectClass SUPERIORS, checking that the type
     * hierarchy is correct.
     */
    private static void buildSuperiors( ObjectClass objectClass, List<Throwable> errors, Registries registries )
    {
        ObjectClassRegistry ocRegistry = registries.getObjectClassRegistry();
        List<String> superiorOids = objectClass.getSuperiorOids();

        if ( superiorOids != null )
        {
            objectClass.getSuperiors().clear();

            for ( String superiorName : superiorOids )
            {
                try
                {
                    ObjectClass superior = ocRegistry.lookup( ocRegistry.getOidByName( superiorName ) );

                    // Before adding the superior, check that the ObjectClass type is consistent
                    switch ( objectClass.getType() )
                    {
                        case ABSTRACT:
                            if ( superior.getType() != ObjectClassTypeEnum.ABSTRACT )
                            {
                                // An ABSTRACT OC can only inherit from ABSTRACT OCs
                                String msg = I18n.err( I18n.ERR_04318, objectClass.getOid(), superior.getObjectType(), superior );

                                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                                    LdapSchemaExceptionCodes.OC_ABSTRACT_MUST_INHERIT_FROM_ABSTRACT_OC, msg );
                                ldapSchemaException.setSourceObject( objectClass );
                                errors.add( ldapSchemaException );
                                LOG.info( msg );

                                continue;
                            }

                            break;

                        case AUXILIARY:
                            if ( superior.getType() == ObjectClassTypeEnum.STRUCTURAL )
                            {
                                // An AUXILIARY OC cannot inherit from STRUCTURAL OCs
                                String msg = I18n.err( I18n.ERR_04319, objectClass.getOid(), superior );

                                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                                    LdapSchemaExceptionCodes.OC_AUXILIARY_CANNOT_INHERIT_FROM_STRUCTURAL_OC, msg );
                                ldapSchemaException.setSourceObject( objectClass );
                                errors.add( ldapSchemaException );
                                LOG.info( msg );

                                continue;
                            }

                            break;

                        case STRUCTURAL:
                            if ( superior.getType() == ObjectClassTypeEnum.AUXILIARY )
                            {
                                // A STRUCTURAL OC cannot inherit from AUXILIARY OCs
                                String msg = I18n.err( I18n.ERR_04320, objectClass.getOid(), superior );

                                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                                    LdapSchemaExceptionCodes.OC_STRUCTURAL_CANNOT_INHERIT_FROM_AUXILIARY_OC, msg );
                                ldapSchemaException.setSourceObject( objectClass );
                                errors.add( ldapSchemaException );
                                LOG.info( msg );

                                continue;
                            }

                            break;

                        default:
                            throw new IllegalArgumentException( "Unexpected ObjectClassTypeEnum: "
                                + objectClass.getType() );
                    }

                    objectClass.getSuperiors().add( superior );
                }
                catch ( LdapException ne )
                {
                    // Cannot find the OC
                    String msg = I18n.err( I18n.ERR_04321, objectClass.getOid(), superiorName );

                    LdapSchemaException ldapSchemaException = new LdapSchemaException(
                        LdapSchemaExceptionCodes.OC_NONEXISTENT_SUPERIOR, msg, ne );
                    ldapSchemaException.setSourceObject( objectClass );
                    ldapSchemaException.setRelatedId( superiorName );
                    errors.add( ldapSchemaException );
                    LOG.info( msg );

                    return;
                }
            }
        }
    }


    /**
     * Build and check the MUST AT for this ObjectClass.
     */
    private static void buildMust( ObjectClass objectClass, List<Throwable> errors, Registries registries )
    {
        AttributeTypeRegistry atRegistry = registries.getAttributeTypeRegistry();
        List<String> mustAttributeTypeOids = objectClass.getMustAttributeTypeOids();

        if ( mustAttributeTypeOids != null )
        {
            objectClass.getMustAttributeTypes().clear();

            for ( String mustAttributeTypeName : mustAttributeTypeOids )
            {
                try
                {
                    AttributeType attributeType = atRegistry.lookup( mustAttributeTypeName );

                    if ( attributeType.isCollective() )
                    {
                        // Collective Attributes are not allowed in MAY or MUST
                        String msg = I18n.err( I18n.ERR_04484_COLLECTIVE_NOT_ALLOWED_IN_MUST, mustAttributeTypeName,
                            objectClass.getOid() );

                        LdapSchemaException ldapSchemaException = new LdapSchemaException(
                            LdapSchemaExceptionCodes.OC_COLLECTIVE_NOT_ALLOWED_IN_MUST, msg );
                        ldapSchemaException.setSourceObject( objectClass );
                        ldapSchemaException.setRelatedId( mustAttributeTypeName );
                        errors.add( ldapSchemaException );
                        LOG.info( msg );

                        continue;
                    }

                    if ( objectClass.getMustAttributeTypes().contains( attributeType ) )
                    {
                        // Already registered : this is an error
                        String msg = I18n.err( I18n.ERR_04324, objectClass.getOid(), mustAttributeTypeName );

                        LdapSchemaException ldapSchemaException = new LdapSchemaException(
                            LdapSchemaExceptionCodes.OC_DUPLICATE_AT_IN_MUST, msg );
                        ldapSchemaException.setSourceObject( objectClass );
                        ldapSchemaException.setRelatedId( mustAttributeTypeName );
                        errors.add( ldapSchemaException );
                        LOG.info( msg );

                        continue;
                    }

                    // Check that the MUST AT is not also present in the MAY AT
                    if ( objectClass.getMayAttributeTypes().contains( attributeType ) )
                    {
                        // Already registered : this is an error
                        String msg = I18n.err( I18n.ERR_04325, objectClass.getOid(), mustAttributeTypeName );

                        LdapSchemaException ldapSchemaException = new LdapSchemaException(
                            LdapSchemaExceptionCodes.OC_DUPLICATE_AT_IN_MAY_AND_MUST,
                            msg );
                        ldapSchemaException.setSourceObject( objectClass );
                        ldapSchemaException.setRelatedId( mustAttributeTypeName );
                        errors.add( ldapSchemaException );
                        LOG.info( msg );

                        continue;
                    }

                    objectClass.getMustAttributeTypes().add( attributeType );
                }
                catch ( LdapException ne )
                {
                    // Cannot find the AT
                    String msg = I18n.err( I18n.ERR_04326, objectClass.getOid(), mustAttributeTypeName );

                    LdapSchemaException ldapSchemaException = new LdapSchemaException(
                        LdapSchemaExceptionCodes.OC_NONEXISTENT_MUST_AT, msg, ne );
                    ldapSchemaException.setSourceObject( objectClass );
                    ldapSchemaException.setRelatedId( mustAttributeTypeName );
                    errors.add( ldapSchemaException );
                    LOG.info( msg );

                    continue;
                }
            }
        }
    }
    
    
    /**
     * Build and check the MAY AT for this ObjectClass
     */
    private static void buildMay( ObjectClass objectClass, List<Throwable> errors, Registries registries )
    {
        AttributeTypeRegistry atRegistry = registries.getAttributeTypeRegistry();
        List<String> mayAttributeTypeOids = objectClass.getMayAttributeTypeOids();

        if ( mayAttributeTypeOids != null )
        {
            objectClass.getMayAttributeTypes().clear();

            for ( String mayAttributeTypeName : mayAttributeTypeOids )
            {
                try
                {
                    AttributeType attributeType = atRegistry.lookup( mayAttributeTypeName );

                    if ( attributeType.isCollective() )
                    {
                        // Collective Attributes are not allowed in MAY or MUST
                        String msg = I18n.err( I18n.ERR_04485_COLLECTIVE_NOT_ALLOWED_IN_MAY, mayAttributeTypeName, objectClass.getOid() );

                        LdapSchemaException ldapSchemaException = new LdapSchemaException(
                            LdapSchemaExceptionCodes.OC_COLLECTIVE_NOT_ALLOWED_IN_MAY, msg );
                        ldapSchemaException.setSourceObject( objectClass );
                        ldapSchemaException.setRelatedId( mayAttributeTypeName );
                        errors.add( ldapSchemaException );
                        LOG.info( msg );

                        continue;
                    }

                    if ( objectClass.getMayAttributeTypes().contains( attributeType ) )
                    {
                        // Already registered : this is an error
                        String msg = I18n.err( I18n.ERR_04322, objectClass.getOid(), mayAttributeTypeName );

                        LdapSchemaException ldapSchemaException = new LdapSchemaException(
                            LdapSchemaExceptionCodes.OC_DUPLICATE_AT_IN_MAY, msg );
                        ldapSchemaException.setSourceObject( objectClass );
                        ldapSchemaException.setRelatedId( mayAttributeTypeName );
                        errors.add( ldapSchemaException );
                        LOG.info( msg );

                        continue;
                    }

                    objectClass.getMayAttributeTypes().add( attributeType );
                }
                catch ( LdapException ne )
                {
                    // Cannot find the AT
                    String msg = I18n.err( I18n.ERR_04323, objectClass.getOid(), mayAttributeTypeName );

                    LdapSchemaException ldapSchemaException = new LdapSchemaException(
                        LdapSchemaExceptionCodes.OC_NONEXISTENT_MAY_AT, msg, ne );
                    ldapSchemaException.setSourceObject( objectClass );
                    ldapSchemaException.setRelatedId( mayAttributeTypeName );
                    errors.add( ldapSchemaException );
                    LOG.info( msg );

                    continue;
                }
            }
        }
    }
    
    
    /**
     * Remove the ObjectClass from the registries, updating the references to
     * other SchemaObject.
     *
     * If one of the referenced SchemaObject does not exist (SUPERIORS, MAY, MUST),
     * an exception is thrown.
     *
     * @param objectClass The ObjectClass to remove fro the registries
     * @param errors The errors we got while removing the ObjectClass from the registries
     * @param registries The Registries
     * @throws LdapException If the ObjectClass is not valid
     */
    public static void removeFromRegistries( ObjectClass objectClass, List<Throwable> errors, Registries registries ) throws LdapException
    {
        if ( registries != null )
        {
            ObjectClassRegistry objectClassRegistry = registries.getObjectClassRegistry();

            // Unregister this ObjectClass into the Descendant map
            objectClassRegistry.unregisterDescendants( objectClass, objectClass.getSuperiors() );

            /**
             * Remove the OC references (using and usedBy) :
             * OC -> AT (for MAY and MUST)
             * OC -> OC
             */
            if ( objectClass.getMayAttributeTypes() != null )
            {
                for ( AttributeType may : objectClass.getMayAttributeTypes() )
                {
                    registries.delReference( objectClass, may );
                }
            }

            if ( objectClass.getMustAttributeTypes() != null )
            {
                for ( AttributeType must : objectClass.getMustAttributeTypes() )
                {
                    registries.delReference( objectClass, must );
                }
            }

            if ( objectClass.getSuperiors() != null )
            {
                for ( ObjectClass superior : objectClass.getSuperiors() )
                {
                    registries.delReference( objectClass, superior );
                }
            }
        }
    }
}
