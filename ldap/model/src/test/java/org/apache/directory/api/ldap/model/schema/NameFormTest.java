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
 * Unit tests class NameForm.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class NameFormTest
{
    private NameForm nameForm;


    /**
     * Initialize attribute type instances
     */
    @Before
    public void initNameForms() throws Exception
    {
        nameForm = new NameForm( "1.2.3.4" );
        nameForm.setNames( "name1", "name2" );
        nameForm.setDescription( "description" );
        nameForm.setObsolete( false );
        nameForm.setStructuralObjectClassOid( "2.3.4.5" );
        nameForm.setMustAttributeTypeOids( Arrays.asList( "must1", "must2" ) );
        nameForm.setMayAttributeTypeOids( Arrays.asList( "may0" ) );
    }


    @Test
    public void testToString() throws Exception
    {
        String string = nameForm.toString();

        assertNotNull( string );
        assertTrue( string.startsWith( "nameform (" ) );
        assertTrue( string.contains( " NAME " ) );
        assertTrue( string.contains( "\n\tDESC " ) );
        assertTrue( string.contains( "\n\tOC" ) );
        assertTrue( string.contains( "\n\tMUST" ) );
        assertTrue( string.contains( "\n\tMAY" ) );
    }
}
