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
package org.apache.directory.api.ldap.model.schema;


import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Unit tests class DitContentRule.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class DitContentRuleTest
{
    private DitContentRule ditContentRule;


    /**
     * Initialize attribute type instances
     */
    @Before
    public void initDitContentRules() throws Exception
    {
        ditContentRule = new DitContentRule( "1.2.3.4" );
        ditContentRule.setNames( "name1", "name2" );
        ditContentRule.setDescription( "description" );
        ditContentRule.setObsolete( false );
        ditContentRule.setAuxObjectClassOids( Arrays.asList( "oc1", "oc2" ) );
        ditContentRule.setMustAttributeTypeOids( Arrays.asList( "must1", "must2" ) );
        ditContentRule.setMayAttributeTypeOids( Arrays.asList( "may1", "may2" ) );
        ditContentRule.setNotAttributeTypeOids( Arrays.asList( "not1", "not2" ) );
    }


    @Test
    public void testToString() throws Exception
    {
        String string = ditContentRule.toString();

        assertNotNull( string );
        assertTrue( string.startsWith( "ditcontentrule (" ) );
        assertTrue( string.contains( " NAME " ) );
        assertTrue( string.contains( "\n\tDESC " ) );
        assertTrue( string.contains( "\n\tAUX " ) );
        assertTrue( string.contains( "\n\tMUST" ) );
        assertTrue( string.contains( "\n\tMAY" ) );
        assertTrue( string.contains( "\n\tNOT" ) );
    }
}
