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


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.normalizers.DeepTrimNormalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A comparator that uses the DeepTrimNormalizer before comparing two values
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DeepTrimComparator extends LdapComparator<String>
{
    /** The serial version UID */
    private static final long serialVersionUID = 2L;

    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( DeepTrimComparator.class );
    
    /**
     * The NormalizingComparator constructor. Its OID is the  matching rule OID.
     * 
     * @param oid The Comparator's OID
     */
    public DeepTrimComparator( String oid )
    {
        super( oid );
        normalizer = new DeepTrimNormalizer();
    }


    /**
     * {@inheritDoc}
     */
    public int compare( String o1, String o2 )
    {
        String n1 = o1;
        String n2;

        try
        {
            n1 = normalizer.normalize( o1 );
        }
        catch ( LdapException e )
        {
            LOG.warn( I18n.msg( I18n.MSG_13700_FAILED_TO_NORMALIZE, o1 ), e );
            n1 = o1;
        }

        try
        {
            n2 = normalizer.normalize( o2 );
        }
        catch ( LdapException e )
        {
            LOG.warn( I18n.msg( I18n.MSG_13700_FAILED_TO_NORMALIZE, o2 ), e );
            n2 = o2;
        }

        return n1.compareTo( n2 );
    }
}
