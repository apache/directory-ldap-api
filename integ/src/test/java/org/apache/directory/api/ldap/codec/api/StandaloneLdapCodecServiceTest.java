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

import org.apache.directory.api.ldap.codec.standalone.StandaloneLdapApiService;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicy;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureRequest;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureRequestImpl;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.util.Strings;
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
        System.setProperty( StandaloneLdapApiService.CONTROLS_LIST,
            "org.apache.directory.api.ldap.codec.controls.cascade.CascadeFactory," +
                "org.apache.directory.api.ldap.codec.controls.manageDsaIT.ManageDsaITFactory," +
                "org.apache.directory.api.ldap.codec.controls.proxiedauthz.ProxiedAuthzFactory," +
                "org.apache.directory.api.ldap.codec.controls.search.entryChange.EntryChangeFactory," +
                "org.apache.directory.api.ldap.codec.controls.search.pagedSearch.PagedResultsFactory," +
                "org.apache.directory.api.ldap.codec.controls.search.persistentSearch.PersistentSearchFactory," +
                "org.apache.directory.api.ldap.codec.controls.search.subentries.SubentriesFactory," +
                "org.apache.directory.api.ldap.extras.controls.ppolicy_impl.PasswordPolicyFactory," +
                "org.apache.directory.api.ldap.extras.controls.vlv_impl.VirtualListViewRequestFactory," +
                "org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncDoneValueFactory," +
                "org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncInfoValueFactory," +
                "org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncRequestValueFactory," +
                "org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncStateValueFactory," +
                "org.apache.directory.api.ldap.extras.controls.ad_impl.AdDirSyncFactory" );

        System.setProperty( StandaloneLdapApiService.EXTENDED_OPERATIONS_LIST,
            "org.apache.directory.api.ldap.extras.extended.ads_impl.cancel.CancelFactory," +
                "org.apache.directory.api.ldap.extras.extended.ads_impl.certGeneration.CertGenerationFactory," +
                "org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulShutdown.GracefulShutdownFactory," +
                "org.apache.directory.api.ldap.extras.extended.ads_impl.storedProcedure.StoredProcedureFactory," +
                "org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify.PasswordModifyFactory," +
                "org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulDisconnect.GracefulDisconnectFactory," +
                "org.apache.directory.api.ldap.extras.extended.ads_impl.whoAmI.WhoAmIFactory," +
                "org.apache.directory.api.ldap.extras.extended.ads_impl.startTls.StartTlsFactory"
            );
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
