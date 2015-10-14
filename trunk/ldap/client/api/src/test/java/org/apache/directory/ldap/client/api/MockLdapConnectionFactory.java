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
package org.apache.directory.ldap.client.api;


import java.util.LinkedList;
import java.util.Queue;

import org.apache.directory.api.ldap.model.exception.LdapException;


public class MockLdapConnectionFactory extends DefaultLdapConnectionFactory
{
    Queue<LdapConnection> connections = new LinkedList<LdapConnection>();


    public MockLdapConnectionFactory( LdapConnectionConfig config )
    {
        super( config );
    }


    public MockLdapConnectionFactory addConnection( LdapConnection connection )
    {
        this.connections.add( connection );
        return this;
    }


    @Override
    public LdapConnection newLdapConnection() throws LdapException
    {
        return bindConnection( this.connections.remove() );
    }


    @Override
    public LdapConnection newUnboundLdapConnection()
    {
        return this.connections.remove();
    }
}