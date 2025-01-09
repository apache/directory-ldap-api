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
package org.apache.directory.api.ldap.model.schema.comparators;



import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.normalizers.NumericNormalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A class for the numericStringOrderingMatch matchingRule (RFC 4517, par. 4.2.23)
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class NumericStringComparator extends LdapComparator<String>
{
    /** Declares the Serial Version Uid */
    private static final long serialVersionUID = 2L;

    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( NumericStringComparator.class );


    /**
     * The IntegerComparator constructor. Its OID is the numericStringOrderingMatch matching
     * rule OID.
     * 
     * @param oid The Comparator's OID
     */
    public NumericStringComparator( String oid )
    {
        super( oid );
    }


    /**
     * {@inheritDoc}
     */
    public int compare( String backendValue, String assertValue )
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_13754_COMPARING_NUMERIC_STRING_ORDERING, backendValue, assertValue ) );
        }

        // First, shortcut the process by comparing
        // references. If they are equals, then o1 and o2
        // reference the same object
        if ( backendValue == assertValue )
        {
            return 0;
        }

        // Then, deal with one of o1 or o2 being null
        // Both can't be null, because then they would
        // have been caught by the previous test
        if ( ( backendValue == null ) || ( assertValue == null ) )
        {
            return backendValue == null ? -1 : 1;
        }

        // Both objects must be stored as String for numeric.
        // But we need to normalize the values first.
        NumericNormalizer normalizer = new NumericNormalizer();

        try
        {
            backendValue = normalizer.normalize( backendValue );
        }
        catch ( LdapException le )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_13724_INVALID_VALUE, backendValue ), le );
        }
        try
        {
            assertValue = normalizer.normalize( assertValue );
        }
        catch ( LdapException le )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_13724_INVALID_VALUE, assertValue ), le );
        }

        return backendValue.compareTo( assertValue );
    }
}
