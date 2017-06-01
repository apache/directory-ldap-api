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
package org.apache.directory.api.osgi;


import org.apache.commons.pool.PoolableObjectFactory;
import org.apache.commons.pool.impl.GenericObjectPool.Config;
import org.apache.directory.ldap.client.api.DefaultPoolableLdapConnectionFactory;
import org.apache.directory.ldap.client.api.Krb5LoginConfiguration;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.SaslGssApiRequest;
import org.apache.directory.ldap.client.api.future.AddFuture;
import org.apache.directory.ldap.client.api.search.FilterBuilder;
import org.apache.directory.ldap.client.template.LdapConnectionTemplate;


public class ApiLdapClientApiOsgiTest extends ApiOsgiTestBase
{

    @Override
    protected String getBundleName()
    {
        return "org.apache.directory.api.ldap.client.api";
    }


    @Override
    protected void useBundleClasses() throws Exception
    {
        new LdapNetworkConnection().close();
        new SaslGssApiRequest();
        new Krb5LoginConfiguration();
        new AddFuture( new LdapNetworkConnection(), 2 );
        new LdapConnectionTemplate( new LdapConnectionPool( new DefaultPoolableLdapConnectionFactory(
            new LdapConnectionConfig() ) ) );
        FilterBuilder.and( FilterBuilder.not( FilterBuilder.contains( "cn", "a", "b" ) ) ).toString();

        // Test for DIRAPI-239
        PoolableObjectFactory<LdapConnection> factory = new DefaultPoolableLdapConnectionFactory(
            new LdapConnectionConfig() );
        Config config = new Config();
        LdapConnectionPool ldapConnectionPool = new LdapConnectionPool( factory, config );
        ldapConnectionPool.getLdapApiService();
        ldapConnectionPool.getTestOnBorrow();
    }

}
