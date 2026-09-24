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


import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.BindResponseImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;


/**
 * Tests that the void bind() helpers only return normally on a SUCCESS result : a caller
 * relying on the absence of exception must never consider an unverified password as
 * valid. A server that does not hold the bind DN may for instance return a REFERRAL
 * without checking the credentials.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class BindResultCodeTest
{
    private static final String USER_DN = "uid=jsmith,ou=people,dc=example,dc=com";


    private static LdapNetworkConnection connectionReturning( ResultCodeEnum resultCode ) throws Exception
    {
        LdapConnectionConfig config = new LdapConnectionConfig();
        config.setName( USER_DN );
        config.setCredentials( "wrong" );

        LdapNetworkConnection connection = spy( new LdapNetworkConnection( config ) );

        BindResponse bindResponse = new BindResponseImpl( 1 );
        bindResponse.getLdapResult().setResultCode( resultCode );
        doReturn( bindResponse ).when( connection ).bind( any( BindRequest.class ) );

        return connection;
    }


    @ParameterizedTest
    @EnumSource( value = ResultCodeEnum.class, names =
        { "REFERRAL", "SASL_BIND_IN_PROGRESS", "PARTIAL_RESULTS", "CANCELED", "COMPARE_TRUE", "COMPARE_FALSE" } )
    public void testNonSuccessResultIsNotAnAuthentication( ResultCodeEnum resultCode ) throws Exception
    {
        try ( LdapNetworkConnection connection = connectionReturning( resultCode ) )
        {
            assertThrows( LdapAuthenticationException.class, () -> connection.bind( USER_DN, "wrong" ) );
            assertThrows( LdapAuthenticationException.class, () -> connection.bind( new Dn( USER_DN ), "wrong" ) );
            assertThrows( LdapAuthenticationException.class, () -> connection.bind( USER_DN ) );
            assertThrows( LdapAuthenticationException.class, () -> connection.bind( new Dn( USER_DN ) ) );
            assertThrows( LdapAuthenticationException.class, () -> connection.bind() );
            assertThrows( LdapAuthenticationException.class, () -> connection.anonymousBind() );
        }
    }


    @ParameterizedTest
    @EnumSource( value = ResultCodeEnum.class, names = { "INVALID_CREDENTIALS" } )
    public void testErrorResultStillThrows( ResultCodeEnum resultCode ) throws Exception
    {
        try ( LdapNetworkConnection connection = connectionReturning( resultCode ) )
        {
            assertThrows( LdapAuthenticationException.class, () -> connection.bind( USER_DN, "wrong" ) );
        }
    }


    @ParameterizedTest
    @EnumSource( value = ResultCodeEnum.class, names = { "SUCCESS" } )
    public void testSuccessIsAnAuthentication( ResultCodeEnum resultCode ) throws Exception
    {
        try ( LdapNetworkConnection connection = connectionReturning( resultCode ) )
        {
            assertDoesNotThrow( () -> connection.bind( USER_DN, "secret" ) );
            assertDoesNotThrow( () -> connection.bind( new Dn( USER_DN ), "secret" ) );
            assertDoesNotThrow( () -> connection.bind() );
            assertDoesNotThrow( () -> connection.anonymousBind() );
        }
    }
}
