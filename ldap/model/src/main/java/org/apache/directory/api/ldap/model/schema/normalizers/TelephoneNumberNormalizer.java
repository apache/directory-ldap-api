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
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.PrepareString;


/**
 * Normalize Telephone Number Strings. We don't process substring differently, as we don't
 * have any significant space in a Telephone Number.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public class TelephoneNumberNormalizer extends Normalizer
{
    /**
     * Creates a new instance of TelephoneNumberNormalizer.
     */
    public TelephoneNumberNormalizer()
    {
        super( SchemaConstants.TELEPHONE_NUMBER_MATCH_MR_OID );
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
    public String normalize( String value, PrepareString.AssertionType assertiontype ) throws LdapException
    {
        if ( value == null )
        {
            return null;
        }

        char[] chars = value.toCharArray();
        
        // Insignificant Characters Handling
        return PrepareString.insignificantTelephoneNumberStringHandling( chars );
    }
}