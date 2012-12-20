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
package org.apache.directory.api.ldap.codec.api;


import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.codec.standalone.StandaloneLdapApiService;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.util.Strings;
import org.apache.directory.shared.ldap.extras.controls.ppolicy.PasswordPolicy;
import org.apache.directory.shared.ldap.extras.extended.StoredProcedureRequest;
import org.apache.directory.shared.ldap.extras.extended.StoredProcedureRequestImpl;
import org.junit.BeforeClass;
import org.junit.Test;


/**
 * Tests for StandaloneLdapCodecService.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StandaloneLdapCodecServiceTest
{
    @BeforeClass
    public static void setupLdapApiService() throws Exception
    {
        // Load the extension points
        System.setProperty( StandaloneLdapApiService.DEFAULT_CONTROLS_LIST,
            "org.apache.directory.api.ldap.codec.controls.cascade.CascadeFactory," +
                "org.apache.directory.api.ldap.codec.controls.manageDsaIT.ManageDsaITFactory," +
                "org.apache.directory.api.ldap.codec.controls.search.entryChange.EntryChangeFactory," +
                "org.apache.directory.api.ldap.codec.controls.search.pagedSearch.PagedResultsFactory," +
                "org.apache.directory.api.ldap.codec.controls.search.persistentSearch.PersistentSearchFactory," +
                "org.apache.directory.api.ldap.codec.controls.search.subentries.SubentriesFactory" );

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
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.codec.standalone.StandaloneLdapCodecService#StandaloneLdapCodecService()}.
     */
    @Test
    public void testLoadingExtras() throws Exception
    {
        LdapApiService codec = LdapApiServiceFactory.getSingleton();

        assertTrue( codec.isControlRegistered( PasswordPolicy.OID ) );

        CodecControl<? extends Control> control = codec.newControl( PasswordPolicy.OID );
        assertNotNull( control );
        assertNotNull( codec );
    }


    /**
     * Test an extended operation.
     */
    @Test
    public void testLoadingExtendedOperation() throws Exception
    {
        LdapApiService codec = LdapApiServiceFactory.getSingleton();
        StoredProcedureRequest req = new StoredProcedureRequestImpl();
        req.setLanguage( "Java" );
        req.setProcedure( Strings.getBytesUtf8( "bogusProc" ) );

        assertNotNull( req );
        assertNotNull( codec );

        StoredProcedureRequest decorator = ( StoredProcedureRequest ) codec.decorate( req );
        assertNotNull( decorator );
    }
}
