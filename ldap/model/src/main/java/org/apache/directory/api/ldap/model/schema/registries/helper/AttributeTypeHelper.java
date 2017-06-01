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

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaExceptionCodes;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.MutableAttributeType;
import org.apache.directory.api.ldap.model.schema.UsageEnum;
import org.apache.directory.api.ldap.model.schema.registries.AttributeTypeRegistry;
import org.apache.directory.api.ldap.model.schema.registries.Registries;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An helper class used to store all the methods associated with an AttributeType
 * in relation with the Registries and SchemaManager.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class AttributeTypeHelper
{
    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( AttributeTypeHelper.class );

    private AttributeTypeHelper()
    {
    }

    /**
     * Inject the AttributeType into the Registries, updating the references to
     * other SchemaObject
     *
     * If one of the referenced SchemaObject does not exist (SUP, EQUALITY, ORDERING, SUBSTR, SYNTAX),
     * an exception is thrown.
     * 
     * @param attributeType The AttributeType to add to the Registries
     * @param errors The errors we got while adding the AttributeType to the Registries
     * @param registries The Registries
     * @throws LdapException If the AttributeType is not valid
     */
    public static void addToRegistries( MutableAttributeType attributeType, List<Throwable> errors, Registries registries ) throws LdapException
    {
        if ( registries != null )
        {
            try
            {
                attributeType.unlock();
                AttributeTypeRegistry attributeTypeRegistry = registries.getAttributeTypeRegistry();
    
                // The superior
                if ( !buildSuperior( attributeType, errors, registries ) )
                {
                    // We have had errors, let's stop here as we need a correct superior to continue
                    return;
                }
    
                // The Syntax
                buildSyntax( attributeType, errors, registries );
    
                // The EQUALITY matching rule
                buildEquality( attributeType, errors, registries );
    
                // The ORDERING matching rule
                buildOrdering( attributeType, errors, registries );
    
                // The SUBSTR matching rule
                buildSubstring( attributeType, errors, registries );
    
                // Check the USAGE
                checkUsage( attributeType, errors );
    
                // Check the COLLECTIVE element
                checkCollective( attributeType, errors );
    
                // Inject the attributeType into the oid/normalizer map
                attributeTypeRegistry.addMappingFor( attributeType );
    
                // Register this AttributeType into the Descendant map
                attributeTypeRegistry.registerDescendants( attributeType, attributeType.getSuperior() );
    
                /**
                 * Add the AT references (using and usedBy) :
                 * AT -> MR (for EQUALITY, ORDERING and SUBSTR)
                 * AT -> S
                 * AT -> AT
                 */
                if ( attributeType.getEquality() != null )
                {
                    registries.addReference( attributeType, attributeType.getEquality() );
                }
    
                if ( attributeType.getOrdering() != null )
                {
                    registries.addReference( attributeType, attributeType.getOrdering() );
                }
    
                if ( attributeType.getSubstring() != null )
                {
                    registries.addReference( attributeType, attributeType.getSubstring() );
                }
    
                if ( attributeType.getSyntax() != null )
                {
                    registries.addReference( attributeType, attributeType.getSyntax() );
                }
    
                if ( attributeType.getSuperior() != null )
                {
                    registries.addReference( attributeType, attributeType.getSuperior() );
                }
            }
            finally
            {
                attributeType.lock();
            }
        }
    }


    /**
     * Build the Superior AttributeType reference for an AttributeType
     */
    private static boolean buildSuperior( MutableAttributeType attributeType, List<Throwable> errors, Registries registries )
    {
        MutableAttributeType currentSuperior;
        AttributeTypeRegistry attributeTypeRegistry = registries.getAttributeTypeRegistry();
        
        String superiorOid = attributeType.getSuperiorOid();

        if ( superiorOid != null )
        {
            // This AT has a superior
            try
            {
                currentSuperior = ( MutableAttributeType ) attributeTypeRegistry.lookup( superiorOid );
            }
            catch ( Exception e )
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_04303, superiorOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_SUPERIOR, msg, e );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( superiorOid );
                errors.add( ldapSchemaException );
                LOG.info( msg );

                // Get out now
                return false;
            }

            if ( currentSuperior != null )
            {
                // a special case : if the superior is collective, this is an error
                if ( currentSuperior.isCollective() )
                {
                    String msg = I18n.err( I18n.ERR_04482_CANNOT_SUBTYPE_COLLECTIVE,
                        currentSuperior, attributeType.getName() );

                    LdapSchemaException ldapSchemaException = new LdapSchemaException(
                        LdapSchemaExceptionCodes.AT_CANNOT_SUBTYPE_COLLECTIVE_AT, msg );
                    ldapSchemaException.setSourceObject( attributeType );
                    errors.add( ldapSchemaException );
                    LOG.info( msg );
                    
                    return false;
                }

                attributeType.setSuperior( currentSuperior );

                // Recursively update the superior if not already done. We don't recurse
                // if the superior's superior is not null, as it means it has already been
                // handled.
                if ( currentSuperior.getSuperior() == null )
                {
                    registries.buildReference( errors, currentSuperior );
                }

                // Update the descendant MAP
                try
                {
                    attributeTypeRegistry.registerDescendants( attributeType, currentSuperior );
                }
                catch ( LdapException ne )
                {
                    errors.add( ne );
                    LOG.info( ne.getMessage() );
                    
                    return false;
                }

                // Check for cycles now
                Set<String> superiors = new HashSet<>();
                superiors.add( attributeType.getOid() );
                AttributeType tmp = currentSuperior;
                boolean isOk = true;

                while ( tmp != null )
                {
                    if ( superiors.contains( tmp.getOid() ) )
                    {
                        // There is a cycle : bad bad bad !
                        // Not allowed.
                        String msg = I18n.err( I18n.ERR_04304, attributeType.getName() );

                        LdapSchemaException ldapSchemaException = new LdapSchemaException(
                            LdapSchemaExceptionCodes.AT_CYCLE_TYPE_HIERARCHY, msg );
                        ldapSchemaException.setSourceObject( attributeType );
                        errors.add( ldapSchemaException );
                        LOG.info( msg );
                        isOk = false;

                        break;
                    }
                    else
                    {
                        superiors.add( tmp.getOid() );
                        tmp = tmp.getSuperior();
                    }
                }

                superiors.clear();

                return isOk;
            }
            else
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_04305, superiorOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_SUPERIOR, msg );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( superiorOid );
                errors.add( ldapSchemaException );
                LOG.info( msg );

                // Get out now
                return false;
            }
        }
        else
        {
            // No superior, just return
            return true;
        }
    }


    /**
     * Build the SYNTAX reference for an AttributeType
     */
    private static void buildSyntax( MutableAttributeType attributeType, List<Throwable> errors, Registries registries )
    {
        String syntaxOid = attributeType.getSyntaxOid();
        
        if ( syntaxOid != null )
        {
            LdapSyntax currentSyntax = null;

            try
            {
                currentSyntax = registries.getLdapSyntaxRegistry().lookup( syntaxOid );
            }
            catch ( LdapException ne )
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_04306, syntaxOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_SYNTAX, msg, ne );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( syntaxOid );
                errors.add( ldapSchemaException );
                LOG.info( msg );
                
                return;
            }

            if ( currentSyntax != null )
            {
                // Update the Syntax reference
                attributeType.setSyntax( currentSyntax );
            }
            else
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_04306, syntaxOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_SYNTAX, msg );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( syntaxOid );
                errors.add( ldapSchemaException );
                LOG.info( msg );
                
                return;
            }
        }
        else
        {
            // We inherit from the superior's syntax, if any
            if ( attributeType.getSuperior() != null )
            {
                if ( attributeType.getSuperior().getSyntax() != null )
                {
                    attributeType.setSyntax( attributeType.getSuperior().getSyntax() );
                }
                else
                {
                    String msg = I18n.err( I18n.ERR_04306, syntaxOid, attributeType.getName() );

                    LdapSchemaException ldapSchemaException = new LdapSchemaException(
                        LdapSchemaExceptionCodes.AT_NONEXISTENT_SYNTAX, msg );
                    ldapSchemaException.setSourceObject( attributeType );
                    ldapSchemaException.setRelatedId( syntaxOid );
                    errors.add( ldapSchemaException );
                    LOG.info( msg );
                    
                    return;
                }
            }
            else
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_04307, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_SYNTAX_OR_SUPERIOR_REQUIRED, msg );
                ldapSchemaException.setSourceObject( attributeType );
                errors.add( ldapSchemaException );
                LOG.info( msg );
                
                return;
            }
        }
    }
    
    
    /**
     * Build the EQUALITY MR reference for an AttributeType
     */
    private static void buildEquality( MutableAttributeType attributeType, List<Throwable> errors, Registries registries )
    {
        String equalityOid = attributeType.getEqualityOid();
        
        // The equality MR. It can be null
        if ( equalityOid != null )
        {
            MatchingRule currentEquality = null;

            try
            {
                currentEquality = registries.getMatchingRuleRegistry().lookup( equalityOid );
            }
            catch ( LdapException ne )
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_04308, equalityOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_EQUALITY_MATCHING_RULE, msg, ne );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( equalityOid );
                errors.add( ldapSchemaException );
                LOG.info( msg );
                
                return;
            }

            if ( currentEquality != null )
            {
                attributeType.setEquality( currentEquality );
                
                // Restore the old equality OID to preserve the user's provided value
                attributeType.setEqualityOid( equalityOid );
            }
            else
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_04309, equalityOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_EQUALITY_MATCHING_RULE, msg );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( equalityOid );
                errors.add( ldapSchemaException );
                LOG.info( msg );
            }
        }
        else
        {
            AttributeType superior = attributeType.getSuperior();
            
            // If the AT has a superior, take its Equality MR if any
            if ( ( superior != null ) && ( superior.getEquality() != null ) )
            {
                attributeType.setEquality( superior.getEquality() );
            }
        }
    }


    /**
     * Build the SUBSTR MR reference for an AttributeType
     */
    private static void buildSubstring( MutableAttributeType attributeType, List<Throwable> errors, Registries registries )
    {
        String substringOid = attributeType.getSubstringOid();
        
        // The Substring MR. It can be null
        if ( substringOid != null )
        {
            MatchingRule currentSubstring = null;

            try
            {
                currentSubstring = registries.getMatchingRuleRegistry().lookup( substringOid );
            }
            catch ( LdapException ne )
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_04312, substringOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_SUBSTRING_MATCHING_RULE, msg, ne );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( substringOid );
                errors.add( ldapSchemaException );
                LOG.info( msg );
                
                return;
            }

            if ( currentSubstring != null )
            {
                attributeType.setSubstring( currentSubstring );
            }
            else
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_04313, substringOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_SUBSTRING_MATCHING_RULE, msg );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( substringOid );
                errors.add( ldapSchemaException );
                LOG.info( msg );
                
                return;
            }
        }
        else
        {
            AttributeType superior = attributeType.getSuperior();
            
            // If the AT has a superior, take its Substring MR if any
            if ( ( superior != null ) && ( superior.getSubstring() != null ) )
            {
                attributeType.setSubstring( superior.getSubstring() );
            }
        }
    }
    
    




    /**
     * Build the ORDERING MR reference for an AttributeType
     */
    private static void buildOrdering( MutableAttributeType attributeType, List<Throwable> errors, Registries registries )
    {
        String orderingOid = attributeType.getOrderingOid();
        
        if ( orderingOid != null )
        {
            MatchingRule currentOrdering = null;

            try
            {
                currentOrdering = registries.getMatchingRuleRegistry().lookup( orderingOid );
            }
            catch ( LdapException ne )
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_04310, orderingOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_ORDERING_MATCHING_RULE, msg, ne );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( orderingOid );
                errors.add( ldapSchemaException );
                LOG.info( msg );
                
                return;
            }

            if ( currentOrdering != null )
            {
                attributeType.setOrdering( currentOrdering );
            }
            else
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_04311, orderingOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_ORDERING_MATCHING_RULE, msg );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( orderingOid );
                errors.add( ldapSchemaException );
                LOG.info( msg );
            }
        }
        else
        {
            AttributeType superior = attributeType.getSuperior();
            
            // If the AT has a superior, take its Ordering MR if any
            if ( ( superior != null ) && ( superior.getOrdering() != null ) )
            {
                attributeType.setOrdering( superior.getOrdering() );
            }
        }
    }

    
    /**
     * Check the constraints for the Usage field.
     */
    private static void checkUsage( AttributeType attributeType, List<Throwable> errors )
    {
        AttributeType superior = attributeType.getSuperior();
        
        // Check that the AT usage is the same that its superior
        if ( ( superior != null ) && ( attributeType.getUsage() != superior.getUsage() ) )
        {
            // This is an error
            String msg = I18n.err( I18n.ERR_04314, attributeType.getName() );

            LdapSchemaException ldapSchemaException = new LdapSchemaException(
                LdapSchemaExceptionCodes.AT_MUST_HAVE_SAME_USAGE_THAN_SUPERIOR, msg );
            ldapSchemaException.setSourceObject( attributeType );
            errors.add( ldapSchemaException );
            LOG.info( msg );
            
            return;
        }

        // Now, check that the AttributeType's USAGE does not conflict
        if ( !attributeType.isUserModifiable() && ( attributeType.getUsage() == UsageEnum.USER_APPLICATIONS ) )
        {
            // Cannot have a not user modifiable AT which is not an operational AT
            String msg = I18n.err( I18n.ERR_04315, attributeType.getName() );

            LdapSchemaException ldapSchemaException = new LdapSchemaException(
                LdapSchemaExceptionCodes.AT_USER_APPLICATIONS_USAGE_MUST_BE_USER_MODIFIABLE, msg );
            ldapSchemaException.setSourceObject( attributeType );
            errors.add( ldapSchemaException );
            LOG.info( msg );
        }
    }


    /**
     * Check the constraints for the Collective field.
     */
    private static void checkCollective( MutableAttributeType attributeType, List<Throwable> errors )
    {
        AttributeType superior = attributeType.getSuperior();

        if ( ( superior != null ) && superior.isCollective() )
        {
            // An AttributeType will be collective if its superior is collective
            attributeType.setCollective( true );
        }

        if ( attributeType.isCollective() && ( attributeType.getUsage() != UsageEnum.USER_APPLICATIONS ) )
        {
            // An AttributeType which is collective must be a USER attributeType
            String msg = I18n.err( I18n.ERR_04316, attributeType.getName() );

            LdapSchemaException ldapSchemaException = new LdapSchemaException(
                LdapSchemaExceptionCodes.AT_COLLECTIVE_MUST_HAVE_USER_APPLICATIONS_USAGE, msg );
            ldapSchemaException.setSourceObject( attributeType );
            errors.add( ldapSchemaException );
            LOG.info( msg );
        }

        if ( attributeType.isCollective() && attributeType.isSingleValued() )
        {
            // A collective attribute must be multi-valued
            String msg = I18n.err( I18n.ERR_04483_COLLECTIVE_NOT_MULTI_VALUED, attributeType.getName() );

            LdapSchemaException ldapSchemaException = new LdapSchemaException(
                LdapSchemaExceptionCodes.AT_COLLECTIVE_CANNOT_BE_SINGLE_VALUED, msg );
            ldapSchemaException.setSourceObject( attributeType );
            errors.add( ldapSchemaException );
            LOG.info( msg );
        }
    }
    
    
    /**
     * Remove the AttributeType from the registries, updating the references to
     * other SchemaObject.
     *
     * If one of the referenced SchemaObject does not exist (SUP, EQUALITY, ORDERING, SUBSTR, SYNTAX),
     * an exception is thrown.
     * 
     * @param attributeType The AttributeType to remove from the Registries
     * @param errors The errors we got while removing the AttributeType from the Registries
     * @param registries The Registries
     * @throws LdapException If the AttributeType is not valid
     */
    public static void removeFromRegistries( AttributeType attributeType, List<Throwable> errors, Registries registries ) throws LdapException
    {
        if ( registries != null )
        {
            AttributeTypeRegistry attributeTypeRegistry = registries.getAttributeTypeRegistry();

            // Remove the attributeType from the oid/normalizer map
            attributeTypeRegistry.removeMappingFor( attributeType );

            // Unregister this AttributeType into the Descendant map
            attributeTypeRegistry.unregisterDescendants( attributeType, attributeType.getSuperior() );

            /**
             * Remove the AT references (using and usedBy) :
             * AT -> MR (for EQUALITY, ORDERING and SUBSTR)
             * AT -> S
             * AT -> AT
             */
            if ( attributeType.getEquality() != null )
            {
                registries.delReference( attributeType, attributeType.getEquality() );
            }

            if ( attributeType.getOrdering() != null )
            {
                registries.delReference( attributeType, attributeType.getOrdering() );
            }

            if ( attributeType.getSubstring() != null )
            {
                registries.delReference( attributeType, attributeType.getSubstring() );
            }

            if ( attributeType.getSyntax() != null )
            {
                registries.delReference( attributeType, attributeType.getSyntax() );
            }

            if ( attributeType.getSuperior() != null )
            {
                registries.delReference( attributeType, attributeType.getSuperior() );
            }
        }
    }
}
