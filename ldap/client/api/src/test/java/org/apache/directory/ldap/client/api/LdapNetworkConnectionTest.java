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


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import org.apache.directory.api.ldap.model.message.BindResponse;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;


/**
 * Tests LdapNetworkConnection.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapNetworkConnectionTest
{

    @Test
    public void testBindSaslCramMd5ForwardsCredentials() throws Exception
    {
        LdapNetworkConnection connection = spy( new LdapNetworkConnection( "localhost", 389 ) );
        doReturn( null ).when( connection ).bind( any( SaslCramMd5Request.class ) );

        ArgumentCaptor<SaslCramMd5Request> captor = ArgumentCaptor.forClass( SaslCramMd5Request.class );

        connection.bindSaslCramMd5( "uid=alice", "correctPassword" );

        verify( connection ).bind( captor.capture() );
        assertEquals( "uid=alice", captor.getValue().getUsername() );
        assertArrayEquals( "correctPassword".getBytes( StandardCharsets.UTF_8 ), captor.getValue().getCredentials(),
            "bindSaslCramMd5 must forward the credentials parameter, not use a hardcoded value" );
    }


    @Test
    public void testBindSaslDigestMd5ForwardsCredentials() throws Exception
    {
        LdapNetworkConnection connection = spy( new LdapNetworkConnection( "localhost", 389 ) );
        doReturn( null ).when( connection ).bind( any( SaslDigestMd5Request.class ) );

        ArgumentCaptor<SaslDigestMd5Request> captor = ArgumentCaptor.forClass( SaslDigestMd5Request.class );

        connection.bindSaslDigestMd5( "uid=alice", "correctPassword" );

        verify( connection ).bind( captor.capture() );
        assertEquals( "uid=alice", captor.getValue().getUsername() );
        assertArrayEquals( "correctPassword".getBytes( StandardCharsets.UTF_8 ), captor.getValue().getCredentials(),
            "bindSaslDigestMd5 must forward the credentials parameter, not use a hardcoded value" );
    }


    private static Stream<Arguments> data()
    {
        // index 0: connection timout in ms
        // index 1: search time limit in seconds
        // index 2: expected timeout in ms
        return Stream.of(
            Arguments.of( 2000, -1, 2000, "Invalid search time limit, use connection timeout" ),
            Arguments.of( 2000, 0, 2000, "Search time limit is 0, use config default value" ),
            Arguments.of( 2000, 1, 2000, "search time limit < connection timeout, use connection timeout" ),
            Arguments.of( 2000, 5, 5000, "search time limit > connection timeout, use search time limit" ),
            Arguments.of( 2000, Integer.MAX_VALUE, 2147483647000L, "Integer overflow" ),
            Arguments.of( 30000, -1, 30000, "Invalid search time limit, use connection timeout" ),
            Arguments.of( 30000, 0, 30000, "Search time limit is 0, use config default value" ),
            Arguments.of( 30000, 1, 30000, "search time limit < connection timeout, use connection timeout" ),
            Arguments.of( 30000, 29, 30000, "search time limit < connection timeout, use connection timeout" ),
            Arguments.of( 30000, 31, 31000, "search time limit > connection timeout, use search time limit" ),
            Arguments.of( 30000, 60, 60000, "search time limit > connection timeout, use search time limit" ),
            Arguments.of( Long.MAX_VALUE, -1, Long.MAX_VALUE, "Invalid search time limit, use connection timeout" ),
            Arguments.of( Long.MAX_VALUE, 0, Long.MAX_VALUE, "Search time limit is 0, use config default value" ),
            Arguments.of( Long.MAX_VALUE, 1, Long.MAX_VALUE,
                "search time limit < connection timeout, use connection timeout" ) );
    }


    @ParameterizedTest
    @MethodSource("data")
    public void testGetClientTimeout( long connectionTimeoutInMS, int searchTimeLimitInSeconds,
        long expectedTimeoutInMS, String testDescription ) throws IOException
    {
        LdapNetworkConnection ldapConnection = null;

        try
        {
            ldapConnection = new LdapNetworkConnection( "localhost", 389 );
            long timeout = ldapConnection.getTimeout( connectionTimeoutInMS, searchTimeLimitInSeconds );
            assertEquals( expectedTimeoutInMS, timeout );
        }
        finally
        {
            if ( ldapConnection != null )
            {
                ldapConnection.close();
            }
        }
    }

}
