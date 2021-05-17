/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with apiService work for additional information
 *   regarding copyright ownership.  The ASF licenses apiService file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use apiService file except in compliance
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
package org.apache.directory.api.ldap.extras;


import java.util.Map;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.IntermediateOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncRequest;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncResponse;
import org.apache.directory.api.ldap.extras.controls.ad.AdPolicyHints;
import org.apache.directory.api.ldap.extras.controls.ad.AdShowDeleted;
import org.apache.directory.api.ldap.extras.controls.ad.TreeDelete;
import org.apache.directory.api.ldap.extras.controls.ad_impl.AdDirSyncRequestFactory;
import org.apache.directory.api.ldap.extras.controls.ad_impl.AdDirSyncResponseFactory;
import org.apache.directory.api.ldap.extras.controls.ad_impl.AdPolicyHintsFactory;
import org.apache.directory.api.ldap.extras.controls.ad_impl.AdShowDeletedFactory;
import org.apache.directory.api.ldap.extras.controls.ad_impl.TreeDeleteFactory;
import org.apache.directory.api.ldap.extras.controls.changeNotifications.ChangeNotifications;
import org.apache.directory.api.ldap.extras.controls.changeNotifications_impl.ChangeNotificationsFactory;
import org.apache.directory.api.ldap.extras.controls.passwordExpired.PasswordExpiredResponse;
import org.apache.directory.api.ldap.extras.controls.passwordExpired_impl.PasswordExpiredResponseFactory;
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
import org.apache.directory.api.ldap.model.message.Control;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A utility class for adding Codec and extended operation factories.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class ExtrasCodecFactoryUtil
{
    private static final Logger LOG = LoggerFactory.getLogger( ExtrasCodecFactoryUtil.class );


    private ExtrasCodecFactoryUtil()
    {
    }


    /**
     * Loads the extras controls.
     *
     * @param apiService The LDAP Service instance to use
     */
    public static void loadExtrasControls( LdapApiService apiService )
    {
        Map<String, ControlFactory<? extends Control>> requestControlFactories = apiService
            .getRequestControlFactories();
        Map<String, ControlFactory<? extends Control>> responseControlFactories = apiService
            .getResponseControlFactories();

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

        // TreeDelete
        ControlFactory<TreeDelete> treeDeleteFactory = new TreeDeleteFactory( apiService );
        requestControlFactories.put( treeDeleteFactory.getOid(), treeDeleteFactory );

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

        // PasswordExpired response
        ControlFactory<PasswordExpiredResponse> passwordExpiredResponseFactory = new PasswordExpiredResponseFactory( apiService );
        responseControlFactories.put( passwordExpiredResponseFactory.getOid(), passwordExpiredResponseFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, passwordExpiredResponseFactory.getOid() ) );
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
        responseControlFactories.put( syncStateValueFactory.getOid(), syncStateValueFactory );

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
     * Load the extras extended operations :
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
     * @param apiService The LdapApiService to use
     */
    public static void loadExtrasExtendedOperations( LdapApiService apiService )
    {
        Map<String, ExtendedOperationFactory> extendedRequestFactories = apiService.getExtendedRequestFactories();
        Map<String, ExtendedOperationFactory> extendedResponseFactories = apiService.getExtendedResponseFactories();
        
        CancelFactory cancelFactory = new CancelFactory( apiService );
        extendedRequestFactories.put( cancelFactory.getOid(), cancelFactory );
        extendedResponseFactories.put( cancelFactory.getOid(), cancelFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, cancelFactory.getOid() ) );
        }

        CertGenerationFactory certGenerationFactory = new CertGenerationFactory( apiService );
        extendedRequestFactories.put( certGenerationFactory.getOid(), certGenerationFactory );
        extendedResponseFactories.put( certGenerationFactory.getOid(), certGenerationFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, certGenerationFactory.getOid() ) );
        }

        EndTransactionFactory endTransactionFactory = new EndTransactionFactory( apiService );
        extendedRequestFactories.put( endTransactionFactory.getOid(), endTransactionFactory );
        extendedResponseFactories.put( endTransactionFactory.getOid(), endTransactionFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, endTransactionFactory.getOid() ) );
        }

        GracefulDisconnectFactory gracefulDisconnectFactory = new GracefulDisconnectFactory( apiService );
        extendedResponseFactories.put( gracefulDisconnectFactory.getOid(), gracefulDisconnectFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, gracefulDisconnectFactory.getOid() ) );
        }

        GracefulShutdownFactory gracefulShutdownFactory = new GracefulShutdownFactory( apiService );
        extendedRequestFactories.put( gracefulShutdownFactory.getOid(), gracefulShutdownFactory );
        extendedResponseFactories.put( gracefulShutdownFactory.getOid(), gracefulShutdownFactory );

        
        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, gracefulShutdownFactory.getOid() ) );
        }

        NoDFactory noticeOfDisconnectFactory = new NoDFactory( apiService );
        extendedResponseFactories.put( noticeOfDisconnectFactory.getOid(), noticeOfDisconnectFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, noticeOfDisconnectFactory.getOid() ) );
        }

        PasswordModifyFactory passwordModifyFactory = new PasswordModifyFactory( apiService );
        extendedRequestFactories.put( passwordModifyFactory.getOid(), passwordModifyFactory );
        extendedResponseFactories.put( passwordModifyFactory.getOid(), passwordModifyFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, passwordModifyFactory.getOid() ) );
        }

        StartTlsFactory startTlsFactory = new StartTlsFactory( apiService );
        extendedRequestFactories.put( startTlsFactory.getOid(), startTlsFactory );
        extendedResponseFactories.put( startTlsFactory.getOid(), startTlsFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, startTlsFactory.getOid() ) );
        }

        StartTransactionFactory startTransactionFactory = new StartTransactionFactory( apiService );
        extendedRequestFactories.put( startTransactionFactory.getOid(), startTransactionFactory );
        extendedResponseFactories.put( startTransactionFactory.getOid(), startTransactionFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, startTransactionFactory.getOid() ) );
        }

        StoredProcedureFactory storedProcedureFactory = new StoredProcedureFactory( apiService );
        extendedRequestFactories.put( storedProcedureFactory.getOid(), storedProcedureFactory );
        extendedResponseFactories.put( storedProcedureFactory.getOid(), storedProcedureFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, storedProcedureFactory.getOid() ) );
        }

        WhoAmIFactory whoAmIFactory = new WhoAmIFactory( apiService );
        extendedRequestFactories.put( whoAmIFactory.getOid(), whoAmIFactory );
        extendedResponseFactories.put( whoAmIFactory.getOid(), whoAmIFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, whoAmIFactory.getOid() ) );
        }
    }


    /**
     * Load the extras intermediate responses :
     * <ul>
     * <li>syncInfovalue</li>
     * </ul>
     *
     * @param apiService The LdapApiService to use
     */
    public static void loadExtrasIntermediateResponses( LdapApiService apiService )
    {
        Map<String, IntermediateOperationFactory> intermediateResponseFactories = apiService
            .getIntermediateResponseFactories();

        SyncInfoValueFactory syncInfoValueFactory = new SyncInfoValueFactory();
        intermediateResponseFactories.put( syncInfoValueFactory.getOid(), syncInfoValueFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06002_REGISTERED_INTERMEDIATE_FACTORY, syncInfoValueFactory.getOid() ) );
        }
    }
}
