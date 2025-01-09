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
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A comparator for TelephoneNumber.
 * 
 * The rules for matching are identical to those for caseIgnoreMatch, except that 
 * all space and "-" characters are skipped during the comparison. 
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class TelephoneNumberComparator extends LdapComparator<String>
{
    /** Declares the Serial Version Uid */
    private static final long serialVersionUID = 2L;

    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( TelephoneNumberComparator.class );

    /**
     * The TelephoneNumberComparator constructor. Its OID is the TelephoneNumberMatch matching
     * rule OID.
     * 
     * @param oid The Comparator's OID
     */
    public TelephoneNumberComparator( String oid )
    {
        super( oid );
    }


    /**
     * Remove all spaces and '-' from the telephone number
     * 
     * @param telephoneNumber The telephoneNumber to strip
     * @return teh stripped telephoneNumber
     */
    private String strip( String telephoneNumber )
    {
        char[] telephoneNumberArray = telephoneNumber.toCharArray();
        int pos = 0;

        for ( char c : telephoneNumberArray )
        {
            if ( ( c == ' ' ) || ( c == '-' ) )
            {
                continue;
            }

            telephoneNumberArray[pos++] = c;
        }

        return new String( telephoneNumberArray, 0, pos );
    }


    /**
     * {@inheritDoc}
     */
    public int compare( String telephoneNumber1, String telephoneNumber2 )
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_13750_COMPARING_TELEPHONE_NUMBER, telephoneNumber1, telephoneNumber2 ) );
        }

        // -------------------------------------------------------------------
        // Handle some basis cases
        // -------------------------------------------------------------------
        if ( telephoneNumber1 == null )
        {
            return ( telephoneNumber2 == null ) ? 0 : -1;
        }

        if ( telephoneNumber2 == null )
        {
            return 1;
        }

        // -------------------------------------------------------------------
        // Remove all spaces and '-'
        // -------------------------------------------------------------------
        String strippedTelephoneNumber1 = strip( telephoneNumber1 );
        String strippedTelephoneNumber2 = strip( telephoneNumber2 );

        return strippedTelephoneNumber1.compareToIgnoreCase( strippedTelephoneNumber2 );
    }
}
