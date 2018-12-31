/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with apiService work for additional information
 *   regarding copyright ownership.  The ASF licenses apiService file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use apiService file except in compliance
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
package org.apache.directory.api.ldap.codec.standalone;


import java.util.Map;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.IntermediateOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.controls.cascade.CascadeFactory;
import org.apache.directory.api.ldap.codec.controls.manageDsaIT.ManageDsaITFactory;
import org.apache.directory.api.ldap.codec.controls.proxiedauthz.ProxiedAuthzFactory;
import org.apache.directory.api.ldap.codec.controls.search.entryChange.EntryChangeFactory;
import org.apache.directory.api.ldap.codec.controls.search.pagedSearch.PagedResultsFactory;
import org.apache.directory.api.ldap.codec.controls.search.persistentSearch.PersistentSearchFactory;
import org.apache.directory.api.ldap.codec.controls.search.subentries.SubentriesFactory;
import org.apache.directory.api.ldap.codec.controls.sort.SortRequestFactory;
import org.apache.directory.api.ldap.codec.controls.sort.SortResponseFactory;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncRequest;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncResponse;
import org.apache.directory.api.ldap.extras.controls.ad.AdPolicyHints;
import org.apache.directory.api.ldap.extras.controls.ad.AdShowDeleted;
import org.apache.directory.api.ldap.extras.controls.ad_impl.AdDirSyncRequestFactory;
import org.apache.directory.api.ldap.extras.controls.ad_impl.AdDirSyncResponseFactory;
import org.apache.directory.api.ldap.extras.controls.ad_impl.AdPolicyHintsFactory;
import org.apache.directory.api.ldap.extras.controls.ad_impl.AdShowDeletedFactory;
import org.apache.directory.api.ldap.extras.controls.changeNotifications.ChangeNotifications;
import org.apache.directory.api.ldap.extras.controls.changeNotifications_impl.ChangeNotificationsFactory;
import org.apache.directory.api.ldap.extras.controls.permissiveModify.PermissiveModify;
import org.apache.directory.api.ldap.extras.controls.permissiveModify_impl.PermissiveModifyFactory;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyRequest;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyResponse;
import org.apache.directory.api.ldap.extras.controls.ppolicy_impl.PasswordPolicyRequestFactory;
import org.apache.directory.api.ldap.extras.controls.ppolicy_impl.PasswordPolicyResponseFactory;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncDone.SyncDoneValue;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncRequest.SyncRequestValue;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncState.SyncStateValue;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncDoneValueFactory;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncRequestValueFactory;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncStateValueFactory;
import org.apache.directory.api.ldap.extras.controls.transaction.TransactionSpecification;
import org.apache.directory.api.ldap.extras.controls.transaction_impl.TransactionSpecificationFactory;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewResponse;
import org.apache.directory.api.ldap.extras.controls.vlv_impl.VirtualListViewRequestFactory;
import org.apache.directory.api.ldap.extras.controls.vlv_impl.VirtualListViewResponseFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.cancel.CancelFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.certGeneration.CertGenerationFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction.EndTransactionFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulDisconnect.GracefulDisconnectFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulShutdown.GracefulShutdownFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.nod.NoDFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify.PasswordModifyFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.startTls.StartTlsFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.startTransaction.StartTransactionFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.storedProcedure.StoredProcedureFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.whoAmI.WhoAmIFactory;
import org.apache.directory.api.ldap.extras.intermediate.syncrepl_impl.SyncInfoValueFactory;
import org.apache.directory.api.ldap.model.message.controls.Cascade;
import org.apache.directory.api.ldap.model.message.controls.EntryChange;
import org.apache.directory.api.ldap.model.message.controls.ManageDsaIT;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.PersistentSearch;
import org.apache.directory.api.ldap.model.message.controls.ProxiedAuthz;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.message.controls.SortResponse;
import org.apache.directory.api.ldap.model.message.controls.Subentries;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A utility class for adding Codec and extended operation factories.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class CodecFactoryUtil
{
    private static final Logger LOG = LoggerFactory.getLogger( CodecFactoryUtil.class );


    private CodecFactoryUtil()
    {
    }


    /**
     * Loads the Controls implement out of the box in the codec.
     *
     * @param requestControlFactories The Request Control factories to use
     * @param responseControlFactories The Response Control factories to use
     * @param apiService The LDAP Service instance to use
     */
    public static void loadStockControls( Map<String, ControlFactory<?>> requestControlFactories,
        Map<String, ControlFactory<?>> responseControlFactories, LdapApiService apiService )
    {
        // Standard controls
        // Cascade
        ControlFactory<Cascade> cascadeFactory = new CascadeFactory( apiService );
        requestControlFactories.put( cascadeFactory.getOid(), cascadeFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, cascadeFactory.getOid() ) );
        }

        // EntryChange
        ControlFactory<EntryChange> entryChangeFactory = new EntryChangeFactory( apiService );
        responseControlFactories.put( entryChangeFactory.getOid(), entryChangeFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, entryChangeFactory.getOid() ) );
        }

        // ManageDsaIT
        ControlFactory<ManageDsaIT> manageDsaITFactory = new ManageDsaITFactory( apiService );
        requestControlFactories.put( manageDsaITFactory.getOid(), manageDsaITFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, manageDsaITFactory.getOid() ) );
        }

        // pagedResults (both a request and response control)
        ControlFactory<PagedResults> pagedResultsFactory = new PagedResultsFactory( apiService );
        requestControlFactories.put( pagedResultsFactory.getOid(), pagedResultsFactory );
        responseControlFactories.put( pagedResultsFactory.getOid(), pagedResultsFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, pagedResultsFactory.getOid() ) );
        }

        // PersistentSearch
        ControlFactory<PersistentSearch> persistentSearchFactory = new PersistentSearchFactory( apiService );
        requestControlFactories.put( persistentSearchFactory.getOid(), persistentSearchFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, persistentSearchFactory.getOid() ) );
        }

        // Proxied
        ControlFactory<ProxiedAuthz> proxiedAuthzFactory = new ProxiedAuthzFactory( apiService );
        requestControlFactories .put( proxiedAuthzFactory.getOid(), proxiedAuthzFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, proxiedAuthzFactory.getOid() ) );
        }

        // SortRequest
        ControlFactory<SortRequest> sortRequestFactory = new SortRequestFactory( apiService );
        requestControlFactories.put( sortRequestFactory.getOid(), sortRequestFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, sortRequestFactory.getOid() ) );
        }

        // SortResponse
        ControlFactory<SortResponse> sortResponseFactory = new SortResponseFactory( apiService );
        responseControlFactories.put( sortResponseFactory.getOid(), sortResponseFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, sortResponseFactory.getOid() ) );
        }

        // Subentries
        ControlFactory<Subentries> subentriesFactory = new SubentriesFactory( apiService );
        requestControlFactories.put( subentriesFactory.getOid(), subentriesFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, subentriesFactory.getOid() ) );
        }

        // Extra controls
        // AdDirSync request
        ControlFactory<AdDirSyncRequest> adDirSyncRequestFactory = new AdDirSyncRequestFactory( apiService );
        requestControlFactories.put( adDirSyncRequestFactory.getOid(), adDirSyncRequestFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, adDirSyncRequestFactory.getOid() ) );
        }

        // AdDirSync response
        ControlFactory<AdDirSyncResponse> adDirSyncResponseFactory = new AdDirSyncResponseFactory( apiService );
        responseControlFactories.put( adDirSyncResponseFactory.getOid(), adDirSyncResponseFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, adDirSyncRequestFactory.getOid() ) );
        }

        // AdPolicyHints
        ControlFactory<AdPolicyHints> adPolicyHintsFactory = new AdPolicyHintsFactory( apiService );
        requestControlFactories.put( adPolicyHintsFactory.getOid(), adPolicyHintsFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, adPolicyHintsFactory.getOid() ) );
        }

        // AdShowDelete
        ControlFactory<AdShowDeleted> adShowDeletedFactory = new AdShowDeletedFactory( apiService );
        requestControlFactories.put( adShowDeletedFactory.getOid(), adShowDeletedFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, adShowDeletedFactory.getOid() ) );
        }

        // ChangeNotification
        ControlFactory<ChangeNotifications> changeNotificationsFactory = new ChangeNotificationsFactory( apiService );
        requestControlFactories.put( changeNotificationsFactory.getOid(), changeNotificationsFactory );
        responseControlFactories.put( changeNotificationsFactory.getOid(), changeNotificationsFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, changeNotificationsFactory.getOid() ) );
        }

        // PasswordPolicy request
        ControlFactory<PasswordPolicyRequest> passwordPolicyRequestFactory = new PasswordPolicyRequestFactory( apiService );
        requestControlFactories.put( passwordPolicyRequestFactory.getOid(), passwordPolicyRequestFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, passwordPolicyRequestFactory.getOid() ) );
        }

        // PasswordPolicy response
        ControlFactory<PasswordPolicyResponse> passwordPolicyResponseFactory = new PasswordPolicyResponseFactory( apiService );
        responseControlFactories.put( passwordPolicyResponseFactory.getOid(), passwordPolicyResponseFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, passwordPolicyResponseFactory.getOid() ) );
        }

        // PermissiveModify
        ControlFactory<PermissiveModify> permissiveModifyFactory = new PermissiveModifyFactory( apiService );
        requestControlFactories.put( permissiveModifyFactory.getOid(), permissiveModifyFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, permissiveModifyFactory.getOid() ) );
        }

        // SyncDoneValue
        ControlFactory<SyncDoneValue> syncDoneValueFactory = new SyncDoneValueFactory( apiService );
        responseControlFactories.put( syncDoneValueFactory.getOid(), syncDoneValueFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, syncDoneValueFactory.getOid() ) );
        }

        // SyncRequestValue
        ControlFactory<SyncRequestValue> syncRequestValueFactory = new SyncRequestValueFactory( apiService );
        requestControlFactories.put( syncRequestValueFactory.getOid(), syncRequestValueFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, syncRequestValueFactory.getOid() ) );
        }

        // SyncStateValue
        ControlFactory<SyncStateValue> syncStateValueFactory = new SyncStateValueFactory( apiService );
        requestControlFactories.put( syncStateValueFactory.getOid(), syncStateValueFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, syncStateValueFactory.getOid() ) );
        }

        // TransactionSpecification
        ControlFactory<TransactionSpecification> transactionSpecificationFactory = new TransactionSpecificationFactory( apiService );
        requestControlFactories.put( transactionSpecificationFactory.getOid(), transactionSpecificationFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, transactionSpecificationFactory.getOid() ) );
        }

        // VirtualListViewRequest
        ControlFactory<VirtualListViewRequest> virtualListViewRequestFactory = new VirtualListViewRequestFactory(
            apiService );
        requestControlFactories.put( virtualListViewRequestFactory.getOid(), virtualListViewRequestFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, virtualListViewRequestFactory.getOid() ) );
        }

        // VirtualListViewResponse
        ControlFactory<VirtualListViewResponse> virtualListViewResponseFactory = new VirtualListViewResponseFactory(
            apiService );
        responseControlFactories.put( virtualListViewResponseFactory.getOid(), virtualListViewResponseFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, virtualListViewResponseFactory.getOid() ) );
        }
    }


    /**
     * Load the standard extended operations :
     * <ul>
     * <li>cancel</li>
     * <li>certGeneration</li>
     * <li>gracefuShutdown</li>
     * <li>storedProcedure</li>
     * <li>gracefulDisconnect</li>
     * <li>passwordModify</li>
     * <li>whoAmI</li>
     * <li>startTls</li>
     * <li>startTransaction</li>
     * </ul>
     *
     * @param extendendOperationsFactories The map of extended operation factories
     * @param apiService The LdapApiService to use
     */
    public static void loadStockExtendedOperations(
        Map<String, ExtendedOperationFactory> extendendRequestFactories, 
        Map<String, ExtendedOperationFactory> extendendResponseFactories, LdapApiService apiService )
    {
        CancelFactory cancelFactory = new CancelFactory( apiService );
        extendendRequestFactories.put( cancelFactory.getOid(), cancelFactory );
        extendendResponseFactories.put( cancelFactory.getOid(), cancelFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, cancelFactory.getOid() ) );
        }

        CertGenerationFactory certGenerationFactory = new CertGenerationFactory( apiService );
        extendendRequestFactories.put( certGenerationFactory.getOid(), certGenerationFactory );
        extendendResponseFactories.put( certGenerationFactory.getOid(), certGenerationFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, certGenerationFactory.getOid() ) );
        }

        EndTransactionFactory endTransactionFactory = new EndTransactionFactory( apiService );
        extendendRequestFactories.put( endTransactionFactory.getOid(), endTransactionFactory );
        extendendResponseFactories.put( endTransactionFactory.getOid(), endTransactionFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, endTransactionFactory.getOid() ) );
        }

        GracefulDisconnectFactory gracefulDisconnectFactory = new GracefulDisconnectFactory( apiService );
        extendendResponseFactories.put( gracefulDisconnectFactory.getOid(), gracefulDisconnectFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, gracefulDisconnectFactory.getOid() ) );
        }

        GracefulShutdownFactory gracefulShutdownFactory = new GracefulShutdownFactory( apiService );
        extendendRequestFactories.put( gracefulShutdownFactory.getOid(), gracefulShutdownFactory );
        extendendResponseFactories.put( gracefulShutdownFactory.getOid(), gracefulShutdownFactory );

        
        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, gracefulShutdownFactory.getOid() ) );
        }

        NoDFactory noticeOfDisconnectFactory = new NoDFactory( apiService );
        extendendResponseFactories.put( noticeOfDisconnectFactory.getOid(), noticeOfDisconnectFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, noticeOfDisconnectFactory.getOid() ) );
        }

        PasswordModifyFactory passwordModifyFactory = new PasswordModifyFactory( apiService );
        extendendRequestFactories.put( passwordModifyFactory.getOid(), passwordModifyFactory );
        extendendResponseFactories.put( passwordModifyFactory.getOid(), passwordModifyFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, passwordModifyFactory.getOid() ) );
        }

        StartTlsFactory startTlsFactory = new StartTlsFactory( apiService );
        extendendRequestFactories.put( startTlsFactory.getOid(), startTlsFactory );
        extendendResponseFactories.put( startTlsFactory.getOid(), startTlsFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, startTlsFactory.getOid() ) );
        }

        StartTransactionFactory startTransactionFactory = new StartTransactionFactory( apiService );
        extendendRequestFactories.put( startTransactionFactory.getOid(), startTransactionFactory );
        extendendResponseFactories.put( startTransactionFactory.getOid(), startTransactionFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, startTransactionFactory.getOid() ) );
        }

        StoredProcedureFactory storedProcedureFactory = new StoredProcedureFactory( apiService );
        extendendRequestFactories.put( storedProcedureFactory.getOid(), storedProcedureFactory );
        extendendResponseFactories.put( storedProcedureFactory.getOid(), storedProcedureFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, storedProcedureFactory.getOid() ) );
        }

        WhoAmIFactory whoAmIFactory = new WhoAmIFactory( apiService );
        extendendRequestFactories.put( whoAmIFactory.getOid(), whoAmIFactory );
        extendendResponseFactories.put( whoAmIFactory.getOid(), whoAmIFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, whoAmIFactory.getOid() ) );
        }
    }


    /**
     * Load the standard intermediate responses :
     * <ul>
     * <li>syncInfovalue</li>
     * </ul>
     *
     * @param intermediateResponseFactories The map of intermediate response factories
     * @param apiService The LdapApiService to use
     */
    public static void loadStockIntermediateResponses(
        Map<String, IntermediateOperationFactory> intermediateResponseFactories, LdapApiService apiService )
    {
        SyncInfoValueFactory syncInfoValueFactory = new SyncInfoValueFactory();
        intermediateResponseFactories.put( syncInfoValueFactory.getOid(), syncInfoValueFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06002_REGISTERED_INTERMEDIATE_FACTORY, syncInfoValueFactory.getOid() ) );
        }
    }
}
