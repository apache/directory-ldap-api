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
package org.apache.directory.api.ldap.codec.api;


import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.directory.api.ldap.codec.standalone.StandaloneLdapApiService;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyRequest;
import org.apache.directory.api.ldap.extras.extended.ads_impl.storedProcedure.StoredProcedureFactory;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureRequest;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureRequestImpl;
import org.apache.directory.api.ldap.extras.intermediate.syncrepl.SyncInfoValue;
import org.apache.directory.api.ldap.extras.intermediate.syncrepl.SyncInfoValueImpl;
import org.apache.directory.api.ldap.extras.intermediate.syncrepl_impl.SyncInfoValueFactory;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;


/**
 * Tests for StandaloneLdapCodecService.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StandaloneLdapCodecServiceTest
{
    @BeforeAll
    public static void setupLdapApiService() throws Exception
    {
        // Load the extension points
        System.setProperty( StandaloneLdapApiService.REQUEST_CONTROLS_LIST,
            "org.apache.directory.api.ldap.codec.controls.cascade.CascadeFactory,"
            + "org.apache.directory.api.ldap.codec.controls.manageDsaIT.ManageDsaITFactory,"
            + "org.apache.directory.api.ldap.codec.controls.search.pagedSearch.PagedResultsFactory,"
            + "org.apache.directory.api.ldap.codec.controls.search.persistentSearch.PersistentSearchFactory,"
            + "org.apache.directory.api.ldap.codec.controls.proxiedauthz.ProxiedAuthzFactory,"
            + "org.apache.directory.api.ldap.codec.controls.sort.SortRequestFactory,"
            + "org.apache.directory.api.ldap.codec.controls.search.subentries.SubentriesFactory,"
            + "org.apache.directory.api.ldap.extras.controls.ad_impl.AdDirSyncRequestFactory,"
            + "org.apache.directory.api.ldap.extras.controls.ad_impl.AdPolicyHintsFactory,"
            + "org.apache.directory.api.ldap.extras.controls.ad_impl.AdShowDeletedFactory,"
            + "org.apache.directory.api.ldap.extras.controls.changeNotifications_impl.ChangeNotificationsFactory,"
            + "org.apache.directory.api.ldap.extras.controls.nameWithEntryUUID_impl.NameWithEntryUUIDFactory,"
            + "org.apache.directory.api.ldap.extras.controls.ppolicy_impl.PasswordPolicyRequestFactory,"
            + "org.apache.directory.api.ldap.extras.controls.permissiveModify_impl.PermissiveModifyFactory,"
            + "org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncRequestValueFactory,"
            + "org.apache.directory.api.ldap.extras.controls.transaction_impl.TransactionSpecificationFactory,"
            + "org.apache.directory.api.ldap.extras.controls.vlv_impl.VirtualListViewRequestFactory," );

        System.setProperty( StandaloneLdapApiService.RESPONSE_CONTROLS_LIST,
            "org.apache.directory.api.ldap.codec.controls.search.entryChange.EntryChangeFactory,"
            + "org.apache.directory.api.ldap.codec.controls.search.pagedSearch.PagedResultsFactory,"
            + "org.apache.directory.api.ldap.codec.controls.sort.SortResponseFactory,"
            + "org.apache.directory.api.ldap.extras.controls.ad_impl.AdDirSyncResponseFactory,"
            + "org.apache.directory.api.ldap.extras.controls.passwordExpired_impl.PasswordExpiredResponseFactory,"
            + "org.apache.directory.api.ldap.extras.controls.ppolicy_impl.PasswordPolicyResponseFactory,"
            + "org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncDoneValueFactory,"
            + "org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncStateValueFactory,"
            + "org.apache.directory.api.ldap.extras.controls.vlv_impl.VirtualListViewResponseFactory" );

        System
            .setProperty(
                StandaloneLdapApiService.EXTENDED_OPERATIONS_LIST,
                "org.apache.directory.api.ldap.extras.extended.ads_impl.cancel.CancelFactory,"
                    + "org.apache.directory.api.ldap.extras.extended.ads_impl.certGeneration.CertGenerationFactory,"
                    + "org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction.EndTransactionFactory,"
                    + "org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulDisconnect.GracefulDisconnectFactory,"
                    + "org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulShutdown.GracefulShutdownFactory,"
                    + "org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify.PasswordModifyFactory,"
                    + "org.apache.directory.api.ldap.extras.extended.ads_impl.startTls.StartTlsFactory,"
                    + "org.apache.directory.api.ldap.extras.extended.ads_impl.startTransaction.StartTransactionFactory,"
                    + "org.apache.directory.api.ldap.extras.extended.ads_impl.storedProcedure.StoredProcedureFactory,"
                    + "org.apache.directory.api.ldap.extras.extended.ads_impl.whoAmI.WhoAmIFactory"
                    );

        System
        .setProperty(
            StandaloneLdapApiService.INTERMEDIATE_RESPONSES_LIST,
                "org.apache.directory.api.ldap.extras.intermediate.syncrepl_impl.SyncInfoValueFactory" );

    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.codec.standalone.StandaloneLdapApiService#StandaloneLdapApiService()}.
     * 
     * @throws Exception If the test failed
     */
    @Test
    public void testLoadingExtras() throws Exception
    {
        LdapApiService codec = LdapApiServiceFactory.getSingleton();

        assertTrue( codec.isControlRegistered( PasswordPolicyRequest.OID ) );

        Control control = codec.getRequestControlFactories().get( PasswordPolicyRequest.OID ).newControl();
        assertNotNull( control );
        assertNotNull( codec );
    }


    /**
     * Test an extended operation.
     * 
     * @throws Exception If the test failed
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
        
        StoredProcedureFactory factory = ( StoredProcedureFactory ) codec.getExtendedRequestFactories().get( 
            StoredProcedureRequest.EXTENSION_OID );
        
        req = factory.newRequest();
        assertNotNull( req );
    }


    /**
     * Test an intermediate response.
     * 
     * @throws Exception If the test failed
     */
    @Test
    public void testLoadingIntermediateResponse() throws Exception
    {
        LdapApiService codec = LdapApiServiceFactory.getSingleton();
        SyncInfoValue syncInfoValue = new SyncInfoValueImpl();
        syncInfoValue.setCookie( Strings.getBytesUtf8( "test" ) );

        assertNotNull( syncInfoValue );
        assertNotNull( codec );

        SyncInfoValueFactory factory = 
            ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().get( 
                SyncInfoValue.OID );
        syncInfoValue = ( SyncInfoValue ) factory.newResponse();
        assertNotNull( syncInfoValue );
    }
}
