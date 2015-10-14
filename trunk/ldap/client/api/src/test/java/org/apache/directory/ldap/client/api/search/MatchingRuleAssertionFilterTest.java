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


import static org.junit.Assert.assertEquals;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.extensible;

import org.junit.Test;


/**
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class MatchingRuleAssertionFilterTest
{
    @Test
    public void testExtensible()
    {
        assertEquals( "(cn:caseExactMatch:=Fred Flintstone)", 
            extensible( "cn", "Fred Flintstone" )
                .setMatchingRule( "caseExactMatch" ).toString() );
        assertEquals( "(cn:=Betty Rubble)",
            extensible( "cn", "Betty Rubble" ).toString() );
        assertEquals( "(sn:dn:2.4.6.8.10:=Barney Rubble)", 
            extensible( "sn", "Barney Rubble" )
                .useDnAttributes()
                .setMatchingRule( "2.4.6.8.10" ).toString() );
        assertEquals( "(o:dn:=Ace Industry)", 
            extensible( "o", "Ace Industry" ) 
                .useDnAttributes().toString() );
        assertEquals( "(:1.2.3:=Wilma Flintstone)", 
            extensible( "Wilma Flintstone" )
                .setMatchingRule( "1.2.3" ).toString() );
        assertEquals( "(:dn:2.4.6.8.10:=Dino)", 
            extensible( "Dino" )
                .useDnAttributes()
                .setMatchingRule( "2.4.6.8.10" ).toString() );
    }
}
