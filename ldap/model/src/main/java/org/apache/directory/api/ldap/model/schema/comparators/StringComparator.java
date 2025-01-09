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

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A comparator for Strings.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StringComparator extends LdapComparator<String> implements Serializable
{
    /** Declares the Serial Version Uid */
    private static final long serialVersionUID = 2L;

    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( StringComparator.class );

    /**
     * The StringComparator constructor. Its OID is the StringMatch matching
     * rule OID.
     * 
     * @param oid The Comparator's OID
     */
    public StringComparator( String oid )
    {
        super( oid );
    }


    /**
     * {@inheritDoc}
     */
    public int compare( String s1, String s2 )
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_13749_COMPARING_STRING, s1, s2 ) );
        }

        if ( s1 == s2 )
        {
            return 0;
        }

        // -------------------------------------------------------------------
        // Handle some basis cases
        // -------------------------------------------------------------------
        if ( s1 == null )
        {
            return -1;
        }

        return s1.compareTo( s2 );
    }
}
