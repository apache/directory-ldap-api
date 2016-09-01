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
package org.apache.directory.api.ldap.model.schema.comparators;


import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A class for the BooleanComparator matchingRule (RFC 4517, par. 4.2.2)
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class BooleanComparator extends LdapComparator<String>
{
    /** The serial version UID */
    private static final long serialVersionUID = 2L;

    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( BooleanComparator.class );


    /**
     * The BooleanComparator constructor. Its OID is the BooleanMatch matching
     * rule OID.
     * 
     * @param oid The Comparator's OID
     */
    public BooleanComparator( String oid )
    {
        super( oid );
    }


    /**
     * {@inheritDoc}
     */
    public int compare( String b1, String b2 )
    {
        LOG.debug( "comparing boolean objects '{}' with '{}'", b1, b2 );

        // First, shortcut the process by comparing
        // references. If they are equals, then o1 and o2
        // reference the same object
        if ( b1 == b2 )
        {
            return 0;
        }

        // Then, deal with one of o1 or o2 being null
        // Both can't be null, because then they would 
        // have been catched by the previous test
        if ( ( b1 == null ) || ( b2 == null ) )
        {
            return b1 == null ? -1 : 1;
        }

        // The boolean should have been stored as 'TRUE' or 'FALSE'
        // into the server, and the compare method will be called
        // with normalized booleans, so no need to upper case them.
        // We don't need to check the assertion value, because we
        // are dealing with booleans.
        boolean boolean1 = Boolean.parseBoolean( b1 );
        boolean boolean2 = Boolean.parseBoolean( b2 );

        if ( boolean1 == boolean2 )
        {
            return 0;
        }

        return boolean1 ? 1 : -1;
    }
}
