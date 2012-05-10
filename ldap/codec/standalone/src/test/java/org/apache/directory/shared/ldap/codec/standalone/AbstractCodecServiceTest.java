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
package org.apache.directory.shared.ldap.codec.standalone;


import org.apache.directory.shared.ldap.codec.api.LdapApiService;
import org.apache.directory.shared.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.shared.ldap.codec.api.LdapEncoder;
import org.apache.directory.shared.ldap.codec.standalone.StandaloneLdapApiService;
import org.junit.AfterClass;
import org.junit.BeforeClass;


/**
 * Initialize the Codec service
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractCodecServiceTest
{
    /** The codec service */
    protected static LdapApiService codec;

    /** The encoder instance */
    protected static LdapEncoder encoder;


    /**
     * Initialize the codec service
     */
    @BeforeClass
    public static void setupLdapApiService() throws Exception
    {
        // Load the extension points
        System.setProperty( StandaloneLdapApiService.DEFAULT_CONTROLS_LIST,
            "org.apache.directory.shared.ldap.codec.controls.cascade.CascadeFactory," +
                "org.apache.directory.shared.ldap.codec.controls.manageDsaIT.ManageDsaITFactory," +
                "org.apache.directory.shared.ldap.codec.controls.search.entryChange.EntryChangeFactory," +
                "org.apache.directory.shared.ldap.codec.controls.search.pagedSearch.PagedResultsFactory," +
                "org.apache.directory.shared.ldap.codec.controls.search.persistentSearch.PersistentSearchFactory," +
                "org.apache.directory.shared.ldap.codec.controls.search.subentries.SubentriesFactory" );

        System.setProperty( StandaloneLdapApiService.EXTRA_CONTROLS_LIST,
            "org.apache.directory.shared.ldap.extras.controls.ppolicy_impl.PasswordPolicyFactory," +
                "org.apache.directory.shared.ldap.extras.controls.syncrepl_impl.SyncDoneValueFactory," +
                "org.apache.directory.shared.ldap.extras.controls.syncrepl_impl.SyncInfoValueFactory," +
                "org.apache.directory.shared.ldap.extras.controls.syncrepl_impl.SyncRequestValueFactory," +
                "org.apache.directory.shared.ldap.extras.controls.syncrepl_impl.SyncStateValueFactory" );

        System.setProperty( StandaloneLdapApiService.DEFAULT_EXTENDED_OPERATION_REQUESTS_LIST,
            "org.apache.directory.shared.ldap.extras.extended.ads_impl.cancel.CancelFactory," +
                "org.apache.directory.shared.ldap.extras.extended.ads_impl.certGeneration.CertGenerationFactory," +
                "org.apache.directory.shared.ldap.extras.extended.ads_impl.gracefulShutdown.GracefulShutdownFactory," +
                "org.apache.directory.shared.ldap.extras.extended.ads_impl.storedProcedure.StoredProcedureFactory" );

        System.setProperty( StandaloneLdapApiService.DEFAULT_EXTENDED_OPERATION_RESPONSES_LIST,
            "org.apache.directory.shared.ldap.extras.extended.ads_impl.gracefulDisconnect.GracefulDisconnectFactory" );

        System.setProperty( StandaloneLdapApiService.EXTRA_EXTENDED_OPERATION_LIST, "" );

        codec = LdapApiServiceFactory.getSingleton();
        encoder = new LdapEncoder( codec );
    }


    /**
     * Shutdown the codec service
     */
    @AfterClass
    public static void tearDownLdapCodecService()
    {
        codec = null;
        encoder = null;
    }
}
