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
package org.apache.directory.api.ldap.model.schema;


import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Unit tests class MatchingRuleUse.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class MatchingRuleUseTest
{
    private MatchingRuleUse matchingRuleUse;


    /**
     * Initialize matching rule use instances
     * 
     * @throws Exception If the setup failed
     */
    @BeforeEach
    public void initMatchingRuleUses() throws Exception
    {
        matchingRuleUse = new MatchingRuleUse( "1.2.3.4" );
        matchingRuleUse.setNames( "name1", "name2" );
        matchingRuleUse.setDescription( "description" );
        matchingRuleUse.setObsolete( false );
        matchingRuleUse.setApplicableAttributeOids( Arrays.asList( "2.3.4.5" ) );
    }


    @Test
    public void testToString() throws Exception
    {
        String string = matchingRuleUse.toString();

        assertNotNull( string );
        assertTrue( string.startsWith( "matchingruleuse (" ) );
        assertTrue( string.contains( " NAME " ) );
        assertTrue( string.contains( "\n\tDESC " ) );
        assertTrue( string.contains( "\n\tAPPLIES " ) );
    }
}
