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
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.MutableMatchingRule;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.comparators.ComparableComparator;
import org.apache.directory.api.ldap.model.schema.normalizers.NoOpNormalizer;
import org.apache.directory.api.ldap.model.schema.registries.Registries;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An helper class used to store all the methods associated with an MatchingRule
 * in relation with the Registries and SchemaManager.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class MatchingRuleHelper
{
    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( MatchingRuleHelper.class );


    private MatchingRuleHelper()
    {
    }


    /**
     * Inject the MatchingRule into the Registries, updating the references to
     * other SchemaObject
     *
     * @param matchingRule The MatchingRule to add to the Registries
     * @param errors The errors we got while adding the MatchingRule to the registries
     * @param registries The Registries
     * @throws LdapException If the addition failed
     */
    @SuppressWarnings("rawtypes")
    public static void addToRegistries( MutableMatchingRule matchingRule, List<Throwable> errors, Registries registries )
        throws LdapException
    {
        if ( registries != null )
        {
            try
            {
                matchingRule.unlock();

                LdapComparator<?> ldapComparator = null;
                Normalizer normalizer = null;
                LdapSyntax ldapSyntax = null;

                try
                {
                    // Gets the associated Comparator
                    ldapComparator = registries.getComparatorRegistry().lookup( matchingRule.getOid() );
                }
                catch ( LdapException ne )
                {
                    // Default to a catch all comparator
                    ldapComparator = new ComparableComparator( matchingRule.getOid() );
                }

                try
                {
                    // Gets the associated Normalizer
                    normalizer = registries.getNormalizerRegistry().lookup( matchingRule.getOid() );
                }
                catch ( LdapException ne )
                {
                    // Default to the NoOp normalizer
                    normalizer = new NoOpNormalizer( matchingRule.getOid() );
                }

                try
                {
                    // Get the associated LdapSyntax
                    ldapSyntax = registries.getLdapSyntaxRegistry().lookup( matchingRule.getSyntaxOid() );
                }
                catch ( LdapException ne )
                {
                    // The Syntax is a mandatory element, it must exist.
                    String msg = I18n.err( I18n.ERR_04317 );

                    LdapSchemaException ldapSchemaException = new LdapSchemaException(
                        LdapSchemaExceptionCodes.MR_NONEXISTENT_SYNTAX, msg, ne );
                    ldapSchemaException.setSourceObject( matchingRule );
                    ldapSchemaException.setRelatedId( matchingRule.getSyntaxOid() );
                    errors.add( ldapSchemaException );
                    LOG.info( msg );
                }

                /**
                 * Add the MR references (using and usedBy) :
                 * MR -> C
                 * MR -> N
                 * MR -> S
                 */
                if ( ldapComparator != null )
                {
                    registries.addReference( matchingRule, ldapComparator );
                    matchingRule.setLdapComparator( ldapComparator );
                }

                if ( normalizer != null )
                {
                    registries.addReference( matchingRule, normalizer );
                    matchingRule.setNormalizer( normalizer );
                }

                if ( ldapSyntax != null )
                {
                    registries.addReference( matchingRule, ldapSyntax );
                    matchingRule.setSyntax( ldapSyntax );
                }
            }
            finally
            {
                matchingRule.lock();
            }
        }
    }


    /**
     * Remove the MatchingRule from the Registries, updating the references to
     * other SchemaObject.
     * 
     * If one of the referenced SchemaObject does not exist,
     * an exception is thrown.
     *
     * @param matchingRule The MatchingRule to remove from the Registries
     * @param errors The errors we got while removing the MatchingRule from the registries
     * @param registries The Registries
     * @throws LdapException If the MatchingRule is not valid
     */
    public static void removeFromRegistries( MatchingRule matchingRule, List<Throwable> errors, Registries registries )
        throws LdapException
    {
        if ( registries != null )
        {
            /**
             * Remove the MR references (using and usedBy) :
             * MR -> C
             * MR -> N
             * MR -> S
             */
            if ( matchingRule.getLdapComparator() != null )
            {
                registries.delReference( matchingRule, matchingRule.getLdapComparator() );
            }

            if ( matchingRule.getSyntax() != null )
            {
                registries.delReference( matchingRule, matchingRule.getSyntax() );
            }

            if ( matchingRule.getNormalizer() != null )
            {
                registries.delReference( matchingRule, matchingRule.getNormalizer() );
            }
        }
    }
}
