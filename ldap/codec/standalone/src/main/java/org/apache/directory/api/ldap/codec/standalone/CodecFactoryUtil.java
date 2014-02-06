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

import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.controls.cascade.CascadeFactory;
import org.apache.directory.api.ldap.codec.controls.manageDsaIT.ManageDsaITFactory;
import org.apache.directory.api.ldap.codec.controls.search.entryChange.EntryChangeFactory;
import org.apache.directory.api.ldap.codec.controls.search.pagedSearch.PagedResultsFactory;
import org.apache.directory.api.ldap.codec.controls.search.persistentSearch.PersistentSearchFactory;
import org.apache.directory.api.ldap.codec.controls.search.subentries.SubentriesFactory;
import org.apache.directory.api.ldap.codec.controls.sort.SortRequestFactory;
import org.apache.directory.api.ldap.codec.controls.sort.SortResponseFactory;
import org.apache.directory.api.ldap.extras.controls.ppolicy_impl.PasswordPolicyFactory;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncDoneValueFactory;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncInfoValueFactory;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncRequestValueFactory;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncStateValueFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.cancel.CancelFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.certGeneration.CertGenerationFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulDisconnect.GracefulDisconnectFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulShutdown.GracefulShutdownFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify.PasswordModifyFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.storedProcedure.StoredProcedureFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A utility class for adding Codec and extended operation factories.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CodecFactoryUtil
{
    private static final Logger LOG = LoggerFactory.getLogger( CodecFactoryUtil.class );
    
    /**
     * Loads the Controls implement out of the box in the codec.
     */
    public static void loadStockControls( Map<String, ControlFactory<?, ?>> controlFactories, LdapApiService apiService )
    {
        ControlFactory<?, ?> factory = new CascadeFactory( apiService );
        controlFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );

        factory = new EntryChangeFactory( apiService );
        controlFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );

        factory = new ManageDsaITFactory( apiService );
        controlFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );

        factory = new PagedResultsFactory( apiService );
        controlFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );

        factory = new PersistentSearchFactory( apiService );
        controlFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );

        factory = new SubentriesFactory( apiService );
        controlFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );
        
        factory = new PasswordPolicyFactory( apiService );
        controlFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );
        
        factory = new SyncDoneValueFactory( apiService );
        controlFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );

        factory = new SyncInfoValueFactory( apiService );
        controlFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );

        factory = new SyncRequestValueFactory( apiService );
        controlFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );

        factory = new SyncStateValueFactory( apiService );
        controlFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );

        factory = new SortRequestFactory( apiService );
        controlFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );

        factory = new SortResponseFactory( apiService );
        controlFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );
    }
    
    
    public static void loadStockExtendedOperations( Map<String, ExtendedOperationFactory<?, ?>> extendendOperationsFactories, LdapApiService apiService )
    {
        ExtendedOperationFactory<?, ?> factory = new CancelFactory( apiService );
        extendendOperationsFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled extended operation factory: {}", factory.getOid() );
        
        factory = new CertGenerationFactory( apiService );
        extendendOperationsFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled extended operation factory: {}", factory.getOid() );
        
        factory = new GracefulShutdownFactory( apiService );
        extendendOperationsFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled extended operation factory: {}", factory.getOid() );
        
        factory = new StoredProcedureFactory( apiService );
        extendendOperationsFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled extended operation factory: {}", factory.getOid() );
        
        factory = new GracefulDisconnectFactory( apiService );
        extendendOperationsFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled extended operation factory: {}", factory.getOid() );
        
        factory = new PasswordModifyFactory( apiService );
        extendendOperationsFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled extended operation factory: {}", factory.getOid() );
    }
}
