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

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.ldap.model.schema.registries.Registries;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.OctetStringSyntaxChecker;


/**
 * An helper class used to store all the methods associated with an LdapSyntax
 * in relation with the Registries and SchemaManager.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class LdapSyntaxHelper
{
    private LdapSyntaxHelper()
    {
    }


    /**
     * Inject the LdapSyntax into the registries, updating the references to
     * other SchemaObject
     *
     * @param ldapSyntax The LdapSyntax to add to the Registries
     * @param errors The errors we got while adding the LdapSyntax to the Registries
     * @param registries The Registries
     * @throws LdapException If the addition failed
     */
    public static void addToRegistries( LdapSyntax ldapSyntax, List<Throwable> errors, Registries registries )
        throws LdapException
    {
        if ( registries != null )
        {
            try
            {
                ldapSyntax.unlock();

                SyntaxChecker syntaxChecker = null;

                try
                {
                    // Gets the associated SyntaxChecker
                    syntaxChecker = registries.getSyntaxCheckerRegistry().lookup( ldapSyntax.getOid() );
                }
                catch ( LdapException ne )
                {
                    // No SyntaxChecker ? Associate the Syntax to a catch all SyntaxChecker
                    syntaxChecker = OctetStringSyntaxChecker.builder().setOid( ldapSyntax.getOid() ).build();
                }

                // Add the references for S :
                // S -> SC
                if ( syntaxChecker != null )
                {
                    registries.addReference( ldapSyntax, syntaxChecker );
                    ldapSyntax.setSyntaxChecker( syntaxChecker );
                }
            }
            finally
            {
                ldapSyntax.lock();
            }
        }
    }


    /**
     * Remove the LdapSyntax from the Registries, updating the references to
     * other SchemaObject.
     * 
     * If one of the referenced SchemaObject does not exist,
     * an exception is thrown.
     *
     * @param ldapSyntax The LdapSyntax to remove from the Registries
     * @param errors The errors we got while removing the LdapSyntax from the Registries
     * @param registries The Registries
     * @throws LdapException If the LdapSyntax is not valid
     */
    public static void removeFromRegistries( LdapSyntax ldapSyntax, List<Throwable> errors, Registries registries )
        throws LdapException
    {
        if ( ( registries != null ) && ( ldapSyntax.getSyntaxChecker() != null ) )
        {
            /**
             * Remove the Syntax references (using and usedBy) :
             * S -> SC
             */
            registries.delReference( ldapSyntax, ldapSyntax.getSyntaxChecker() );
        }
    }
}
