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


import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A comparator for UUID. We simply use the UUID compareTo method.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class UuidComparator extends SerializableComparator<String>
{
    /** The serial version UID */
    private static final long serialVersionUID = 2L;

    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( UuidComparator.class );
    private static final boolean IS_DEBUG = LOG.isDebugEnabled();

    /** A static instance of the UuidComparator */
    public static final UuidComparator INSTANCE = new UuidComparator( "1.3.6.1.1.16.4" );


    /**
     * The UUIDComparator constructor. Its OID is the UUIDMatch matching
     * rule OID.
     * 
     * @param oid The Comparator's OID
     */
    public UuidComparator( String oid )
    {
        super( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int compare( String uuid1, String uuid2 )
    {
        if ( IS_DEBUG )
        {
            LOG.debug( "comparing UUID objects '{}' with '{}'", uuid1, uuid2 );
        }

        // -------------------------------------------------------------------
        // Handle some basis cases
        // -------------------------------------------------------------------
        if ( uuid1 == null )
        {
            return ( uuid2 == null ) ? 0 : -1;
        }

        if ( uuid2 == null )
        {
            return 1;
        }

        return uuid1.compareTo( uuid2 );
    }


    /**
     * Compare two UUID.
     * 
     * @param uuid1 The first UUID
     * @param uuid2 he second UUID
     * @return -1 if the first UUID is lower than the second UUID, 1 if it's higher, 0
     * if they are equal  
     */
    public int compare( UUID uuid1, UUID uuid2 )
    {
        if ( IS_DEBUG )
        {
            LOG.debug( "comparing UUID objects '{}' with '{}'", uuid1, uuid2 );
        }

        // -------------------------------------------------------------------
        // Handle some basis cases
        // -------------------------------------------------------------------
        if ( uuid1 == null )
        {
            return ( uuid2 == null ) ? 0 : -1;
        }

        if ( uuid2 == null )
        {
            return 1;
        }

        return uuid1.compareTo( uuid2 );
    }
}
