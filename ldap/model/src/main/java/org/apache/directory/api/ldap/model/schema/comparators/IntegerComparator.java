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


import java.io.Serializable;
import java.math.BigInteger;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.normalizers.NumericNormalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A class for the integerOrderingMatch matchingRule (RFC 4517, par. 4.2.20)
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class IntegerComparator extends LdapComparator<Object> implements Serializable
{
    /** Declares the Serial Version Uid */
    private static final long serialVersionUID = 2L;

    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( IntegerComparator.class );


    /**
     * The IntegerComparator constructor. Its OID is the IntegerOrderingMatch matching
     * rule OID.
     * 
     * @param oid The Comparator's OID
     */
    public IntegerComparator( String oid )
    {
        super( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int compare( Object v1, Object v2 )
    {
        // The value can be a String, a Value or a Long
        if ( v1 == null )
        {
            if ( v2 == null )
            {
                return 0;
            }
            else
            {
                return -1;
            }
        }
        else if ( v2 == null )
        {
            return 1;
        }
        
        if ( v1 instanceof String )
        {
            return compare( ( String ) v1, ( String ) v2 );
        }
        else if ( v1 instanceof Value )
        {
            return compare( ( ( Value ) v1 ).getString(), ( ( Value ) v2 ).getString() ); 
        }
        else 
        {
            return Long.compare( ( Long ) v1, ( Long ) v2 );
        }
    }


    /**
     * Implementation of the Compare method
     * 
     * @param backendValue The stored value
     * @param assertValue The provided value
     * @return <code>0</code> if the values are equal, <code>-1</code> if the provided value is below
     * the stored value, <code>+1</code> otherwise
     */
    private int compare( String backendValue, String assertValue )
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_13746_COMPARING_INTEGER, backendValue, assertValue ) );
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
        
        try
        {
            // First try with longs
            Long l1 = Long.valueOf( backendValue );
            Long l2 = Long.valueOf( assertValue );
            
            return l1.compareTo( l2 );
        }
        catch ( NumberFormatException nfe )
        {
            // Ok, try with BigIntegers
            BigInteger b1 = new BigInteger( backendValue );
            BigInteger b2 = new BigInteger( assertValue );
    
            return b1.compareTo( b2 );
        }
    }
}
