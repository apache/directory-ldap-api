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


import java.text.ParseException;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.util.GeneralizedTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A class for the generalizedTimeOrderingMatch matchingRule (RFC 4517, par. 4.2.17)
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class GeneralizedTimeComparator extends LdapComparator<String>
{
    /** The serial version UID */
    private static final long serialVersionUID = 2L;

    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( GeneralizedTimeComparator.class );


    /**
     * The GeneralizedTimeComparator constructor. Its OID is the
     * generalizedTimeOrderingMatch matching rule OID.
     * 
     * @param oid The Comparator's OID
     */
    public GeneralizedTimeComparator( String oid )
    {
        super( oid );
    }


    /**
     * {@inheritDoc}
     */
    public int compare( String backendValue, String assertValue )
    {
        LOG.debug( I18n.msg( I18n.MSG_13753_COMPARING_GENERALIZED_TIME_ORDERING, backendValue, assertValue ) );

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

        // Both objects must be stored as String for generalized tim.
        // But we need to normalize the values first.
        GeneralizedTime backendTime;
        try
        {
            backendTime = new GeneralizedTime( backendValue );
        }
        catch ( ParseException pe )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_13724_INVALID_VALUE, backendValue ), pe );
        }

        GeneralizedTime assertTime;
        
        try
        {
            assertTime = new GeneralizedTime( assertValue );
        }
        catch ( ParseException pe )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_13724_INVALID_VALUE, assertValue ), pe );
        }

        return backendTime.compareTo( assertTime );
    }
}
