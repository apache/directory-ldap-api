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
package org.apache.directory.api.ldap.codec;


import java.util.Map;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
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
import org.apache.directory.api.ldap.model.message.Control;
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
public final class StockCodecFactoryUtil
{
    private static final Logger LOG = LoggerFactory.getLogger( StockCodecFactoryUtil.class );


    private StockCodecFactoryUtil()
    {
    }


    /**
     * Loads the Controls implement out of the box in the codec.
     *
     * @param apiService The LDAP Service instance to use
     */
    public static void loadStockControls( LdapApiService apiService )
    {
        Map<String, ControlFactory<? extends Control>> requestControlFactories = apiService
            .getRequestControlFactories();
        Map<String, ControlFactory<? extends Control>> responseControlFactories = apiService
            .getResponseControlFactories();

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
        requestControlFactories.put( proxiedAuthzFactory.getOid(), proxiedAuthzFactory );

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
    }

}
