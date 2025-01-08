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
package org.apache.directory.api.ldap.model.schema.registries.helper;

import java.util.HashSet;
import java.util.Set;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaExceptionCodes;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.SchemaErrorHandler;
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
     * @param errorHandler Error handler
     * @param registries The Registries
     * @throws LdapException If the AttributeType is not valid
     */
    public static void addToRegistries( AttributeType attributeType, SchemaErrorHandler errorHandler, Registries registries ) throws LdapException
    {
        if ( registries != null )
        {
            try
            {
                attributeType.unlock();
                AttributeTypeRegistry attributeTypeRegistry = registries.getAttributeTypeRegistry();
    
                // The superior
                if ( !buildSuperior( attributeType, errorHandler, registries ) )
                {
                    // We have had errors, let's stop here as we need a correct superior to continue
                    return;
                }
    
                // The Syntax
                buildSyntax( attributeType, errorHandler, registries );
    
                // The EQUALITY matching rule
                buildEquality( attributeType, errorHandler, registries );
    
                // The ORDERING matching rule
                buildOrdering( attributeType, errorHandler, registries );
    
                // The SUBSTR matching rule
                buildSubstring( attributeType, errorHandler, registries );
    
                // Check the USAGE
                checkUsage( attributeType, errorHandler );
    
                // Check the COLLECTIVE element
                checkCollective( attributeType, errorHandler );
    
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
     * 
     * @param attributeType The AttributeType to process
     * @param errorHandler The error handler
     * @param registries The Registries instance
     * @return <code>true</code> if the AttributeType superiors hierarchy is correct, or if we don't have any superior
     */
    private static boolean buildSuperior( AttributeType attributeType, SchemaErrorHandler errorHandler, 
            Registries registries )
    {
        AttributeType currentSuperior;
        AttributeTypeRegistry attributeTypeRegistry = registries.getAttributeTypeRegistry();
        
        String superiorOid = attributeType.getSuperiorOid();

        if ( superiorOid != null )
        {
            // This AT has a superior
            try
            {
                currentSuperior = ( AttributeType ) attributeTypeRegistry.lookup( superiorOid );
            }
            catch ( Exception e )
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_13752_CANNOT_FIND_SUPERIOR, superiorOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_SUPERIOR, msg, e );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( superiorOid );
                errorHandler.handle( LOG, msg, ldapSchemaException );

                // Get out now
                return false;
            }

            if ( currentSuperior != null )
            {
                // a special case : if the superior is collective, this is an error
                if ( currentSuperior.isCollective() )
                {
                    String msg = I18n.err( I18n.ERR_13776_CANNOT_SUBTYPE_COLLECTIVE,
                        currentSuperior, attributeType.getName() );

                    LdapSchemaException ldapSchemaException = new LdapSchemaException(
                        LdapSchemaExceptionCodes.AT_CANNOT_SUBTYPE_COLLECTIVE_AT, msg );
                    ldapSchemaException.setSourceObject( attributeType );
                    errorHandler.handle( LOG, msg, ldapSchemaException );
                    
                    return false;
                }

                attributeType.setSuperior( currentSuperior );

                // Recursively update the superior if not already done. We don't recurse
                // if the superior's superior is not null, as it means it has already been
                // handled.
                if ( currentSuperior.getSuperior() == null )
                {
                    registries.buildReference( currentSuperior );
                }

                // Update the descendant MAP
                try
                {
                    attributeTypeRegistry.registerDescendants( attributeType, currentSuperior );
                }
                catch ( LdapException ne )
                {
                    errorHandler.handle( LOG, ne.getMessage(), ne );
                    
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
                        String msg = I18n.err( I18n.ERR_13753_CYCLE_DETECTED, attributeType.getName() );

                        LdapSchemaException ldapSchemaException = new LdapSchemaException(
                            LdapSchemaExceptionCodes.AT_CYCLE_TYPE_HIERARCHY, msg );
                        ldapSchemaException.setSourceObject( attributeType );
                        errorHandler.handle( LOG, msg, ldapSchemaException );

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
                String msg = I18n.err( I18n.ERR_13752_CANNOT_FIND_SUPERIOR, superiorOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_SUPERIOR, msg );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( superiorOid );
                errorHandler.handle( LOG, msg, ldapSchemaException );

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
     * 
     * @param attributeType The AttributeType to process
     * @param errorHandler The error handler
     * @param registries The Registries instance
     */
    private static void buildSyntax( AttributeType attributeType, SchemaErrorHandler errorHandler, 
            Registries registries )
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
                String msg = I18n.err( I18n.ERR_13754_CANNOT_FIND_SYNTAX, syntaxOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_SYNTAX, msg, ne );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( syntaxOid );
                errorHandler.handle( LOG, msg, ldapSchemaException );
                
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
                String msg = I18n.err( I18n.ERR_13754_CANNOT_FIND_SYNTAX, syntaxOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_SYNTAX, msg );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( syntaxOid );
                errorHandler.handle( LOG, msg, ldapSchemaException );
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
                    String msg = I18n.err( I18n.ERR_13754_CANNOT_FIND_SYNTAX, syntaxOid, attributeType.getName() );

                    LdapSchemaException ldapSchemaException = new LdapSchemaException(
                        LdapSchemaExceptionCodes.AT_NONEXISTENT_SYNTAX, msg );
                    ldapSchemaException.setSourceObject( attributeType );
                    ldapSchemaException.setRelatedId( syntaxOid );
                    errorHandler.handle( LOG, msg, ldapSchemaException );
                }
            }
            else
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_13755_AT_MUST_HAVE_A_SYNTAX_OID, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_SYNTAX_OR_SUPERIOR_REQUIRED, msg );
                ldapSchemaException.setSourceObject( attributeType );
                errorHandler.handle( LOG, msg, ldapSchemaException );
            }
        }
    }
    
    
    /**
     * Build the EQUALITY MR reference for an AttributeType
     * 
     * @param attributeType The AttributeType to process
     * @param errorHandler The error handler
     * @param registries The Registries instance
     */
    private static void buildEquality( AttributeType attributeType, SchemaErrorHandler errorHandler, 
            Registries registries )
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
                String msg = I18n.err( I18n.ERR_13756_CANNOT_FIND_EQUALITY_MR_OBJECT, equalityOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_EQUALITY_MATCHING_RULE, msg, ne );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( equalityOid );
                errorHandler.handle( LOG, msg, ldapSchemaException );
                
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
                String msg = I18n.err( I18n.ERR_13757_CANNOT_FIND_EQUALITY_MR_INSTANCE, equalityOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_EQUALITY_MATCHING_RULE, msg );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( equalityOid );
                errorHandler.handle( LOG, msg, ldapSchemaException );
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
     * 
     * @param attributeType The AttributeType to process
     * @param errorHandler The error handler
     * @param registries The Registries instance
     */
    private static void buildSubstring( AttributeType attributeType, SchemaErrorHandler errorHandler,
            Registries registries )
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
                String msg = I18n.err( I18n.ERR_13760_CANNOT_FIND_SUBSTR_MR_OBJECT, substringOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_SUBSTRING_MATCHING_RULE, msg, ne );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( substringOid );
                errorHandler.handle( LOG, msg, ldapSchemaException );
                
                return;
            }

            if ( currentSubstring != null )
            {
                attributeType.setSubstring( currentSubstring );
            }
            else
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_13761_CANNOT_FIND_SUBSTR_MR_INSTANCE, substringOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_SUBSTRING_MATCHING_RULE, msg );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( substringOid );
                errorHandler.handle( LOG, msg, ldapSchemaException );
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
     * 
     * @param attributeType The AttributeType to process
     * @param errorHandler The error handler
     * @param registries The Registries instance
     */
    private static void buildOrdering( AttributeType attributeType, SchemaErrorHandler errorHandler, 
            Registries registries )
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
                String msg = I18n.err( I18n.ERR_13758_CANNOT_FIND_ORDERING_MR_OBJECT, orderingOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_ORDERING_MATCHING_RULE, msg, ne );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( orderingOid );
                errorHandler.handle( LOG, msg, ldapSchemaException );
                
                return;
            }

            if ( currentOrdering != null )
            {
                attributeType.setOrdering( currentOrdering );
            }
            else
            {
                // Not allowed.
                String msg = I18n.err( I18n.ERR_13759_CANNOT_FIND_ORDERING_MR_INSTANCE, orderingOid, attributeType.getName() );

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.AT_NONEXISTENT_ORDERING_MATCHING_RULE, msg );
                ldapSchemaException.setSourceObject( attributeType );
                ldapSchemaException.setRelatedId( orderingOid );
                errorHandler.handle( LOG, msg, ldapSchemaException );
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
     * 
     * @param attributeType The AttributeType to check
     * @param errorHandler The error handler
     */
    private static void checkUsage( AttributeType attributeType, SchemaErrorHandler errorHandler )
    {
        AttributeType superior = attributeType.getSuperior();
        
        // Check that the AT usage is the same that its superior
        if ( ( superior != null ) && ( attributeType.getUsage() != superior.getUsage() ) )
        {
            // This is an error
            String msg = I18n.err( I18n.ERR_13762_AT_MUST_HAVE_SUPERIOR_USAGE, attributeType.getName() );

            LdapSchemaException ldapSchemaException = new LdapSchemaException(
                LdapSchemaExceptionCodes.AT_MUST_HAVE_SAME_USAGE_THAN_SUPERIOR, msg );
            ldapSchemaException.setSourceObject( attributeType );
            errorHandler.handle( LOG, msg, ldapSchemaException );
            
            return;
        }

        // Now, check that the AttributeType's USAGE does not conflict
        if ( !attributeType.isUserModifiable() && ( attributeType.getUsage() == UsageEnum.USER_APPLICATIONS ) )
        {
            // Cannot have a not user modifiable AT which is not an operational AT
            String msg = I18n.err( I18n.ERR_13763_AT_MUST_BE_USER_MODIFIABLE, attributeType.getName() );

            LdapSchemaException ldapSchemaException = new LdapSchemaException(
                LdapSchemaExceptionCodes.AT_USER_APPLICATIONS_USAGE_MUST_BE_USER_MODIFIABLE, msg );
            ldapSchemaException.setSourceObject( attributeType );
            errorHandler.handle( LOG, msg, ldapSchemaException );
        }
    }


    /**
     * Check the constraints for the Collective field.
     * 
     * @param attributeType The AttributeType to check
     * @param errorHandler The error handler
     */
    private static void checkCollective( AttributeType attributeType, SchemaErrorHandler errorHandler )
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
            String msg = I18n.err( I18n.ERR_13764_AT_COLLECTIVE_SHOULD_BE_USER_APP, attributeType.getName() );

            LdapSchemaException ldapSchemaException = new LdapSchemaException(
                LdapSchemaExceptionCodes.AT_COLLECTIVE_MUST_HAVE_USER_APPLICATIONS_USAGE, msg );
            ldapSchemaException.setSourceObject( attributeType );
            errorHandler.handle( LOG, msg, ldapSchemaException );
        }

        if ( attributeType.isCollective() && attributeType.isSingleValued() )
        {
            // A collective attribute must be multi-valued
            String msg = I18n.err( I18n.ERR_13777_COLLECTIVE_NOT_MULTI_VALUED, attributeType.getName() );

            LdapSchemaException ldapSchemaException = new LdapSchemaException(
                LdapSchemaExceptionCodes.AT_COLLECTIVE_CANNOT_BE_SINGLE_VALUED, msg );
            ldapSchemaException.setSourceObject( attributeType );
            errorHandler.handle( LOG, msg, ldapSchemaException );
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
     * @param errorHandler Error handler
     * @param registries The Registries
     * @throws LdapException If the AttributeType is not valid
     */
    public static void removeFromRegistries( AttributeType attributeType, SchemaErrorHandler errorHandler, Registries registries ) throws LdapException
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
