/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.ldap.client.api;


import java.io.IOException;
import org.apache.commons.pool2.PooledObject;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;


public class PooledLdapConnectionTest
{
    private static class PooledObjectAnswer implements Answer<PooledObject<LdapConnection>> {

        private PooledObject<LdapConnection> result;

        public PooledObject<LdapConnection> getResult() {
            return result;
        }
        @Override
        public PooledObject<LdapConnection> answer(InvocationOnMock invocationOnMock) throws Throwable {
            result = (PooledObject) invocationOnMock.callRealMethod();
            return result;
        }
    }
    
    
    @Test
    void closeReleasesToPool() throws IOException, LdapException
    {
        LdapConnectionPool pool = mock( LdapConnectionPool.class );
        LdapConnection connection = mock( LdapConnection.class );
        PooledLdapConnection spyPooledConnection = spy( new PooledLdapConnection( connection, pool ) );

        try ( PooledLdapConnection pooledConnection = spyPooledConnection )
        {
            pooledConnection.isConnected();
        }

        verify( connection ).isConnected(); // called inside the try-with-resources block
        verify( spyPooledConnection ).close(); // auto-closed
        verify( pool ).releaseConnection( connection ); // close called releaseConnection
    }
    
    
    @Test
    void closeReleasesToPoolValidatingFactory() throws IOException, LdapException
    {
        LdapConnection connection = mock( LdapConnection.class );
        final LdapConnectionConfig config = new LdapConnectionConfig();
        final DefaultLdapConnectionFactory connectionFactory = spy(new DefaultLdapConnectionFactory(config));
        doReturn(connection).when(connectionFactory).newLdapConnection();
        doReturn(connection).when(connectionFactory).newUnboundLdapConnection();
        final ValidatingPoolableLdapConnectionFactory validatingFactory = spy(new ValidatingPoolableLdapConnectionFactory(connectionFactory));
        // We need to capture the result of the makeObject call in the validating connection factory,
        // because the validating connection factory wraps the network connection with a different object
        // (MonitoringLdapConnection).
        final PooledObjectAnswer answer = new PooledObjectAnswer();
        doAnswer(answer).when(validatingFactory).makeObject();
        LdapConnectionPool pool = spy(new LdapConnectionPool( validatingFactory ));
        final PooledLdapConnection spyPooledConnection = spy((PooledLdapConnection) pool.getConnection());
        try(PooledLdapConnection pooledConnection = spyPooledConnection)
        {
            pooledConnection.isConnected();
        }
        verify( spyPooledConnection ).isConnected(); // called inside the try-with-resources block
        verify(spyPooledConnection).close(); // auto close
        verify( pool ).releaseConnection( answer.getResult().getObject() ); // close called releaseConnection with the monitored connection
    }

    @Test
    void closeReleasesToPoolNonValidatingFactory() throws IOException, LdapException
    {
        LdapConnection connection = mock( LdapConnection.class );
        final LdapConnectionConfig config = new LdapConnectionConfig();
        final DefaultLdapConnectionFactory connectionFactory = spy(new DefaultLdapConnectionFactory(config));
        doReturn(connection).when(connectionFactory).newLdapConnection();
        doReturn(connection).when(connectionFactory).newUnboundLdapConnection();
        LdapConnectionPool pool = spy(new LdapConnectionPool( new DefaultPoolableLdapConnectionFactory(connectionFactory) ));
        final PooledLdapConnection spyPooledConnection = spy((PooledLdapConnection) pool.getConnection());
        try(PooledLdapConnection pooledConnection = spyPooledConnection)
        {
            pooledConnection.isConnected();
        }
        verify( spyPooledConnection ).isConnected(); // called inside the try-with-resources block
        verify(spyPooledConnection).close(); // auto close
        verify( pool ).releaseConnection( connection ); // close called releaseConnection
    }


    // use manually by adding @Test, simply adjust ldap server host and port
    void e2e() throws IOException, LdapException
    {
        final String testLdapHOst = "ldap-testing-host";
        final LdapConnectionConfig config = new LdapConnectionConfig();
        config.setLdapPort(389);
        config.setLdapHost(testLdapHOst);
        LdapConnectionPool pool = spy(new LdapConnectionPool(new ValidatingPoolableLdapConnectionFactory(config)));
        try  {
            final LdapConnection connection = pool.getConnection();
            Assertions.assertTrue(connection.isConnected());
            Assertions.assertDoesNotThrow(() -> connection.close());
        } catch(final Exception e) {
            Assertions.fail(e);
        }
        verify(pool, times(1)).releaseConnection(any(LdapConnection.class));
    }
}