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


import java.io.Serializable;

import org.apache.directory.api.ldap.model.schema.LdapComparator;


/**
 * A Dummy comparator used for tests
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DummyComparator extends LdapComparator<String> implements Serializable
{
    /** The serial version UID */
    private static final long serialVersionUID = 2L;


    /**
     * The DummyComparator constructor. Its OID is the StringOrderingMatch matching
     * rule OID.
     */
    public DummyComparator( String oid )
    {
        super( oid );
    }


    /**
     * Compare two objects.
     * 
     * @param obj1 First object
     * @param obj2 Second object
     * @return 1 if obj1 > obj2, 0 if obj1 == obj2, -1 if obj1 < obj2
     */
    public int compare( String obj1, String obj2 )
    {
        if ( obj1 == obj2 )
        {
            return 0;
        }

        return obj1.compareTo( obj2 );
    }
}
