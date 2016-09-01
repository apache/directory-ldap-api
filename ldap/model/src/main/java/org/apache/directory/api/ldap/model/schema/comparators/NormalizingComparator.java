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


import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A comparator which normalizes a value first before using a subordinate
 * comparator to compare them.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class NormalizingComparator extends LdapComparator<String>
{
    /** The serial version UID */
    private static final long serialVersionUID = 2L;

    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( NormalizingComparator.class );

    /** the Normalizer to normalize values with before comparing */
    private Normalizer normalizer;

    /** the underlying comparator to use for comparisons */
    private LdapComparator<String> comparator;

    private boolean onServer = false;


    /**
     * A comparator which normalizes a value first before comparing them.
     * 
     * @param oid The Comparator's OID
     * @param normalizer the Normalizer to normalize values with before comparing
     * @param comparator the underlying comparator to use for comparisons
     */
    public NormalizingComparator( String oid, Normalizer normalizer, LdapComparator<String> comparator )
    {
        super( oid );
        this.normalizer = normalizer;
        this.comparator = comparator;
    }


    /**
     * {@inheritDoc}
     */
    public int compare( String o1, String o2 )
    {
        if ( onServer )
        {
            return comparator.compare( o1, o2 );
        }

        String n1;
        String n2;

        try
        {
            n1 = normalizer.normalize( o1 );
        }
        catch ( LdapException e )
        {
            LOG.warn( "Failed to normalize: " + o1, e );
            n1 = o1;
        }

        try
        {
            n2 = normalizer.normalize( o2 );
        }
        catch ( LdapException e )
        {
            LOG.warn( "Failed to normalize: " + o2, e );
            n2 = o2;
        }

        return comparator.compare( n1, n2 );
    }


    /**
     * {@inheritDoc}
     * 
     * This implementation makes sure we update the oid property of the contained normalizer and 
     * comparator.
     */
    @Override
    public void setOid( String oid )
    {
        super.setOid( oid );
        normalizer.setOid( oid );
        comparator.setOid( oid );
    }


    /**
     * tells that the normalizingComparator should not normalize values which are
     * already normalized on the server 
     */
    public void setOnServer()
    {
        this.onServer = true;
    }
}
