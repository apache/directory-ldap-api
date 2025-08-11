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
package org.apache.directory.api.ldap.model.schema.normalizers;


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapOtherException;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.PrepareString;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.NumericOidSyntaxChecker;
import org.apache.directory.api.util.Strings;


/**
 * A name or numeric id normalizer.  Needs an OID registry to operate properly.
 * The OID registry is injected into this class after instantiation if a 
 * setSchemaManager(SchemaManager) method is exposed.
 * 
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public class NameOrNumericIdNormalizer extends Normalizer
{
    private NumericOidSyntaxChecker checker = NumericOidSyntaxChecker.INSTANCE;

    /** A reference to the schema manager used to normalize the Name */
    private transient SchemaManager schemaManager;

    /** A static instance of this normalizer */
    public static final NameOrNumericIdNormalizer INSTANCE = new NameOrNumericIdNormalizer();


    /**
     * Creates a new instance of NameOrNumericIdNormalizer.
     */
    public NameOrNumericIdNormalizer()
    {
        super( SchemaConstants.NAME_OR_NUMERIC_ID_MATCH_OID );
    }


    /**
     * {@inheritDoc} 
     */
    @Override
    public String normalize( String value ) throws LdapException
    {
        return normalize( value, PrepareString.AssertionType.ATTRIBUTE_VALUE );
    }


    /**
     * {@inheritDoc} 
     */
    @Override
    public String normalize( String value, PrepareString.AssertionType assertionType ) throws LdapException
    {
        if ( Strings.isEmpty( value ) )
        {
            return value;
        }

        // if value is a numeric id then return it as is
        if ( checker.isValidSyntax( value ) )
        {
            return value;
        }

        // if it is a name we need to do a lookup
        String oid = schemaManager.getRegistries().getOid( value );

        if ( oid != null )
        {
            return oid;
        }

        // if all else fails and the schema is not in relaxed mode, throw an exception
        if ( schemaManager.isStrict() )
        {
            throw new LdapOtherException( I18n.err( I18n.ERR_13725_CANNOT_HANDLE_NAME_AND_OPTIONAL_UID_NORM, value ) );
        }
        else
        {
            return value;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setSchemaManager( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;
    }
}
