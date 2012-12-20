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
package org.apache.directory.api.ldap.model.schema.normalizers;


import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.util.Strings;


/**
 * A Dummy normalizer used for tests.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public class DummyNormalizer extends Normalizer
{
    /** A Dummy normalizer */
    private static final DummyNormalizer NORMALIZER = new DummyNormalizer();


    public DummyNormalizer()
    {
        super( SchemaConstants.CASE_IGNORE_MATCH_MR_OID );
    }


    /**
     * {@inheritDoc}
     */
    public Value<?> normalize( Value<?> value ) throws LdapException
    {
        String str = value.getString();

        if ( Strings.isEmpty( str ) )
        {
            return new StringValue( str );
        }

        return new StringValue( str );
    }


    /**
     * {@inheritDoc}
     */
    public String normalize( String value ) throws LdapException
    {
        if ( Strings.isEmpty( value ) )
        {
            return value;
        }

        return value;
    }


    /**
     * Normalize the given String
     *
     * @param string The string to normalize
     * @return The normalized object
     * @throws LdapException If the normalization throws an error
     */
    public static String normalizeString( String string ) throws LdapException
    {
        return NORMALIZER.normalize( string );
    }
}
