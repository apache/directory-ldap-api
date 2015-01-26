/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.ldap.client.api.search;


import static org.apache.directory.ldap.client.api.search.FilterBuilder.and;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.not;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.or;
import static org.junit.Assert.assertEquals;

import org.junit.Test;


/**
 * 
 * TODO FilterBuilderTest.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class FilterBuilderTest
{
    @Test
    public void testFilterBuilder()
    {
        assertEquals( "(cn=Babs Jensen)", equal( "cn", "Babs Jensen" ).toString() );
        assertEquals( "(!(cn=Tim Howes))", not( equal( "cn", "Tim Howes" ) ).toString() );
        assertEquals( "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))",
            and( equal( "objectClass", "Person" ),
                or( equal( "sn", "Jensen" ),
                    equal( "cn", "Babs J*" ) ) ).toString() );
        assertEquals( "(o=univ*of*mich*)", equal( "o", "univ*of*mich*" ).toString() );
    }
}
