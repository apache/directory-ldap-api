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
package org.apache.directory.api.ldap.model.name;


import static org.junit.jupiter.api.Assertions.assertThrows;

import org.apache.directory.api.ldap.model.exception.LdapException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Testcase devised specifically for DIRSERVER-584.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @see <a href="https://issues.apache.org/jira/browse/DIRSERVER-584">DIRSERVER-584</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class DnParserDIRSERVER_584_Test
{
    /**
     * Need this testa() to run first to mess up the state of the static parser.
     * 
     * @throws Exception If the test failed
     */
    @Test
    public void testa() throws Exception
    {
        assertThrows( LdapException.class, () -> 
        {
            new Dn( "ou=test+testing" );
        } );
    }


    /**
     * Need this testb() to run second to use the mess up static parser.  This
     * test should succeed but fails.
     * 
     * @throws Exception If the test failed
     */
    @Test
    public void testb() throws Exception
    {
        new Dn( "ou=system" );
    }
}
