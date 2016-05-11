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
import org.apache.directory.api.ldap.model.schema.normalizers.DeepTrimToLowerNormalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A comparator that uses the DeepTrimToLowerNormalizer before comparing two values
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DeepTrimToLowerComparator extends LdapComparator<String>
{
    /** The serial version UID */
    private static final long serialVersionUID = 2L;

    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( DeepTrimToLowerComparator.class );
    
    /** The associated normalizer */
    private Normalizer normalizer = new DeepTrimToLowerNormalizer();


    /**
     * The NormalizingComparator constructor. Its OID is the  matching rule OID.
     */
    public DeepTrimToLowerComparator( String oid )
    {
        super( oid );
    }


    /**
     * If any normalization attempt fails we compare using the unnormalized
     * object.
     */
    public int compare( String key, String value )
    {
        String normalizedValue;

        try
        {
            normalizedValue = normalizer.normalize( value );
        }
        catch ( LdapException e )
        {
            LOG.warn( "Failed to normalize: " + value, e );
            normalizedValue = value;
        }

        return key.compareTo( normalizedValue );
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public Normalizer getNormalizer()
    {
        return normalizer;
    }
}
