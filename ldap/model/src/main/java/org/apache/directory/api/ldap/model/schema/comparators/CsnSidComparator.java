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
 * A comparator for CSN SID.
 *
 * The SID is supposed to be an hexadecimal number between 0x0 and 0xfff
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CsnSidComparator extends LdapComparator<String>
{
    /** Declares the Serial Version Uid */
    private static final long serialVersionUID = 2L;

    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( CsnSidComparator.class );


    /**
     * The CsnSidComparator constructor. Its OID is the CsnSidMatch matching
     * rule OID.
     * 
     * @param oid The Comparator's OID
     */
    public CsnSidComparator( String oid )
    {
        super( oid );
    }


    /**
     * {@inheritDoc}
     */
    public int compare( String sidStr1, String sidStr2 )
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_13744_COMPARING_CSN_SID, sidStr1, sidStr2 ) );
        }

        // -------------------------------------------------------------------
        // Handle some basis cases
        // -------------------------------------------------------------------
        if ( sidStr1 == null )
        {
            return ( sidStr2 == null ) ? 0 : -1;
        }

        if ( sidStr2 == null )
        {
            return 1;
        }

        int sid1 = 0;
        int sid2;

        try
        {
            sid1 = Integer.parseInt( sidStr1, 16 );
        }
        catch ( NumberFormatException nfe )
        {
            return -1;
        }

        try
        {
            sid2 = Integer.parseInt( sidStr2, 16 );
        }
        catch ( NumberFormatException nfe )
        {
            return 1;
        }

        if ( sid1 > sid2 )
        {
            return 1;
        }
        else if ( sid2 > sid1 )
        {
            return -1;
        }

        return 0;
    }
}
