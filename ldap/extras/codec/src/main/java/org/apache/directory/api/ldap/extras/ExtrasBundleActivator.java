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
package org.apache.directory.api.ldap.extras;


import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ad.AdShowDeleted;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSync;
import org.apache.directory.api.ldap.extras.controls.ad_impl.AdShowDeletedFactory;
import org.apache.directory.api.ldap.extras.controls.ad_impl.AdDirSyncFactory;
import org.apache.directory.api.ldap.extras.controls.changeNotifications.ChangeNotifications;
import org.apache.directory.api.ldap.extras.controls.changeNotifications_impl.ChangeNotificationsFactory;
import org.apache.directory.api.ldap.extras.controls.permissiveModify.PermissiveModify;
import org.apache.directory.api.ldap.extras.controls.permissiveModify_impl.PermissiveModifyFactory;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicy;
import org.apache.directory.api.ldap.extras.controls.ppolicy_impl.PasswordPolicyFactory;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncDone.SyncDoneValue;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncInfoValue.SyncInfoValue;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncInfoValue.SyncRequestValue;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncState.SyncStateValue;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncDoneValueFactory;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncInfoValueFactory;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncRequestValueFactory;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncStateValueFactory;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewResponse;
import org.apache.directory.api.ldap.extras.controls.vlv_impl.VirtualListViewRequestFactory;
import org.apache.directory.api.ldap.extras.controls.vlv_impl.VirtualListViewResponseFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.cancel.CancelFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.certGeneration.CertGenerationFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulDisconnect.GracefulDisconnectFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulShutdown.GracefulShutdownFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify.PasswordModifyFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.startTls.StartTlsFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.storedProcedure.StoredProcedureFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.whoAmI.WhoAmIFactory;
import org.apache.directory.api.ldap.extras.extended.cancel.CancelRequest;
import org.apache.directory.api.ldap.extras.extended.certGeneration.CertGenerationRequest;
import org.apache.directory.api.ldap.extras.extended.gracefulDisconnect.GracefulDisconnectResponse;
import org.apache.directory.api.ldap.extras.extended.gracefulShutdown.GracefulShutdownRequest;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequest;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsRequest;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureRequest;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIRequest;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.util.tracker.ServiceTracker;
import org.osgi.util.tracker.ServiceTrackerCustomizer;


/**
 * A BundleActivator for the ldap codec extras extension: extra ApacheDS and 
 * Apache Directory Studio specific controls and extended operations. 
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ExtrasBundleActivator implements BundleActivator
{

    private ServiceTracker<LdapApiService, LdapApiService> serviceTracker;

    class LdapApiServiceTracker implements ServiceTrackerCustomizer<LdapApiService, LdapApiService>
    {

        private BundleContext context;


        LdapApiServiceTracker( BundleContext context )
        {
            this.context = context;
        }


        @Override
        public LdapApiService addingService( ServiceReference<LdapApiService> reference )
        {
            LdapApiService ldapApiService = context.getService( reference );
            registerExtrasControls( ldapApiService );
            registerExtrasExtendedOps( ldapApiService );
            return ldapApiService;
        }


        @Override
        public void modifiedService( ServiceReference<LdapApiService> reference, LdapApiService ldapApiService )
        {
        }


        @Override
        public void removedService( ServiceReference<LdapApiService> reference, LdapApiService ldapApiService )
        {
            unregisterExtrasControls( ldapApiService );
            unregisterExtrasExtendedOps( ldapApiService );
        }


        /**
         * Registers all the extras extended operations present in this control pack.
         *
         * @param codec The codec service.
         */
        private void registerExtrasExtendedOps( LdapApiService codec )
        {
            // --------------------------------------------------------------------
            // Register Extended Request Factories
            // --------------------------------------------------------------------

            CancelFactory cancelFactory = new CancelFactory( codec );
            codec.registerExtendedRequest( cancelFactory );

            CertGenerationFactory certGenerationFactory = new CertGenerationFactory( codec );
            codec.registerExtendedRequest( certGenerationFactory );

            GracefulShutdownFactory gracefulShutdownFactory = new GracefulShutdownFactory( codec );
            codec.registerExtendedRequest( gracefulShutdownFactory );

            StoredProcedureFactory storedProcedureFactory = new StoredProcedureFactory( codec );
            codec.registerExtendedRequest( storedProcedureFactory );

            PasswordModifyFactory passwordModifyFactory = new PasswordModifyFactory( codec );
            codec.registerExtendedRequest( passwordModifyFactory );

            GracefulDisconnectFactory gracefulDisconnectFactory = new GracefulDisconnectFactory( codec );
            codec.registerExtendedRequest( gracefulDisconnectFactory );

            WhoAmIFactory whoAmIFactory = new WhoAmIFactory( codec );
            codec.registerExtendedRequest( whoAmIFactory );

            StartTlsFactory startTlsFactory = new StartTlsFactory( codec );
            codec.registerExtendedRequest( startTlsFactory );
        }


        private void unregisterExtrasControls( LdapApiService codec )
        {
            codec.unregisterControl( SyncDoneValue.OID );
            codec.unregisterControl( SyncInfoValue.OID );
            codec.unregisterControl( SyncRequestValue.OID );
            codec.unregisterControl( SyncStateValue.OID );
            codec.unregisterControl( PasswordPolicy.OID );
            codec.unregisterControl( AdDirSync.OID );
            codec.unregisterControl( AdShowDeleted.OID );
        }


        private void unregisterExtrasExtendedOps( LdapApiService codec )
        {
            codec.unregisterExtendedRequest( CancelRequest.EXTENSION_OID );
            codec.unregisterExtendedRequest( CertGenerationRequest.EXTENSION_OID );
            codec.unregisterExtendedRequest( GracefulShutdownRequest.EXTENSION_OID );
            codec.unregisterExtendedRequest( StoredProcedureRequest.EXTENSION_OID );
            codec.unregisterExtendedRequest( GracefulDisconnectResponse.EXTENSION_OID );
            codec.unregisterExtendedRequest( PasswordModifyRequest.EXTENSION_OID );
            codec.unregisterExtendedRequest( WhoAmIRequest.EXTENSION_OID );
            codec.unregisterExtendedRequest( StartTlsRequest.EXTENSION_OID );
        }


        /**
         * Registers all the extras controls present in this control pack.
         *
         * @param codec The codec service.
         */
        private void registerExtrasControls( LdapApiService codec )
        {
            ControlFactory<AdDirSync> adDirSyncFactory = new AdDirSyncFactory( codec );
            codec.registerControl( adDirSyncFactory );
            
            ControlFactory<AdShowDeleted> adDeletedFactory = new AdShowDeletedFactory( codec );
            codec.registerControl( adDeletedFactory );
            
            ControlFactory<ChangeNotifications> changeNotificationsFactory = new ChangeNotificationsFactory( codec );
            codec.registerControl( changeNotificationsFactory );

            ControlFactory<PasswordPolicy> passwordPolicyFactory = new PasswordPolicyFactory( codec );
            codec.registerControl( passwordPolicyFactory );

            ControlFactory<PermissiveModify> permissiveModifyFactory = new PermissiveModifyFactory( codec );
            codec.registerControl( permissiveModifyFactory );
            
            ControlFactory<SyncDoneValue> syncDoneValuefactory = new SyncDoneValueFactory( codec );
            codec.registerControl( syncDoneValuefactory );

            ControlFactory<SyncInfoValue> syncInfoValueFactory = new SyncInfoValueFactory( codec );
            codec.registerControl( syncInfoValueFactory );

            ControlFactory<SyncRequestValue> syncRequestValueFactory = new SyncRequestValueFactory( codec );
            codec.registerControl( syncRequestValueFactory );

            ControlFactory<SyncStateValue> syncStateValuefactory = new SyncStateValueFactory( codec );
            codec.registerControl( syncStateValuefactory );

            ControlFactory<VirtualListViewRequest> virtualListViewRequestFactory = new VirtualListViewRequestFactory( codec );
            codec.registerControl( virtualListViewRequestFactory );

            ControlFactory<VirtualListViewResponse> virtualListViewResponseFactory = new VirtualListViewResponseFactory(
                codec );
            codec.registerControl( virtualListViewResponseFactory );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void start( BundleContext context ) throws Exception
    {
        LdapApiServiceTracker ldapApiServiceTracker = new LdapApiServiceTracker( context );
        serviceTracker = new ServiceTracker<>(
            context, LdapApiService.class, ldapApiServiceTracker );
        serviceTracker.open();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void stop( BundleContext context ) throws Exception
    {
        serviceTracker.close();
    }
}
