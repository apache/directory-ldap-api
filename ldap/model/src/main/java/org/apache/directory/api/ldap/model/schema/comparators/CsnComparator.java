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
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A comparator for CSN.
 *
 * The CSN are ordered depending on an evaluation of its component, in this order :
 * - time, 
 * - changeCount,
 * - sid
 * - modifierNumber
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CsnComparator extends LdapComparator<Object>
{
    /** Declares the Serial Version Uid */
    private static final long serialVersionUID = 2L;

    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( CsnComparator.class );


    /**
     * The CsnComparator constructor. Its OID is the CsnMatch matching
     * rule OID.
     * 
     * @param oid The Comparator's OID
     */
    public CsnComparator( String oid )
    {
        super( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int compare( Object csnObj1, Object csnObj2 )
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_13745_COMPARING_CSN, csnObj1, csnObj2 ) );
        }

        if ( csnObj1 == csnObj2 )
        {
            return 0;
        }

        // -------------------------------------------------------------------
        // Handle some basis cases
        // -------------------------------------------------------------------
        if ( csnObj1 == null )
        {
            return -1;
        }

        if ( csnObj2 == null )
        {
            return 1;
        }

        String csnStr1;
        String csnStr2;

        if ( csnObj1 instanceof Value )
        {
            csnStr1 = ( ( Value ) csnObj1 ).getString();
        }
        else
        {
            csnStr1 = csnObj1.toString();
        }

        if ( csnObj2 instanceof Value )
        {
            csnStr2 = ( ( Value ) csnObj2 ).getString();
        }
        else
        {
            csnStr2 = csnObj2.toString();
        }

        return csnStr1.compareTo( csnStr2 );
    }
}
