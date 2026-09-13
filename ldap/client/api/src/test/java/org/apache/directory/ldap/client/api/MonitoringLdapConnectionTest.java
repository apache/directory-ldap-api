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
package org.apache.directory.ldap.client.api;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.io.IOException;

import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsRequestImpl;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.OpaqueExtendedRequest;
import org.junit.jupiter.api.Test;


/**
 * Tests the StartTLS detection of {@link MonitoringLdapConnection} : the typed
 * {@link org.apache.directory.api.ldap.model.message.ExtendedRequest} overload must
 * classify the operation by the request OID, exactly like the String/Oid overloads do.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class MonitoringLdapConnectionTest
{
    @Test
    public void testTypedStartTlsRequestSetsStartTlsCalled() throws LdapException, IOException
    {
        LdapConnection connection = mock( LdapConnection.class );
        
        try ( MonitoringLdapConnection monitor = new MonitoringLdapConnection( connection ) )
        {
            // The canonical typed StartTLS call : it carries no control, its identity
            // is its requestName OID
            monitor.extended( new StartTlsRequestImpl() );
    
            assertTrue( monitor.startTlsCalled() );
        }
    }


    @Test
    public void testOtherTypedExtendedRequestDoesNotSetStartTlsCalled() throws LdapException, IOException
    {
        LdapConnection connection = mock( LdapConnection.class );
        
        try ( MonitoringLdapConnection monitor = new MonitoringLdapConnection( connection ) )
        {
            monitor.extended( new OpaqueExtendedRequest( "1.2.3.4" ) );
    
            assertFalse( monitor.startTlsCalled() );
        }
    }
}
