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
package org.apache.directory.api.ldap.extras;


import java.util.ArrayList;

import org.apache.directory.api.ldap.codec.StockCodecFactoryUtil;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
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
            StockCodecFactoryUtil.loadStockControls( ldapApiService );
            ExtrasCodecFactoryUtil.loadExtrasControls( ldapApiService );
            ExtrasCodecFactoryUtil.loadExtrasExtendedOperations( ldapApiService );
            ExtrasCodecFactoryUtil.loadExtrasIntermediateResponses( ldapApiService );
            return ldapApiService;
        }


        @Override
        public void modifiedService( ServiceReference<LdapApiService> reference, LdapApiService ldapApiService )
        {
        }


        @Override
        public void removedService( ServiceReference<LdapApiService> reference, LdapApiService ldapApiService )
        {
            // Request controls
            for ( String oid : new ArrayList<>( ldapApiService.getRequestControlFactories().keySet() ) )
            {
                ldapApiService.unregisterRequestControl( oid );
            }
            // Response controls
            for ( String oid : new ArrayList<>( ldapApiService.getResponseControlFactories().keySet() ) )
            {
                ldapApiService.unregisterResponseControl( oid );
            }
            // Extended requests
            for ( String oid : new ArrayList<>( ldapApiService.getExtendedRequestFactories().keySet() ) )
            {
                ldapApiService.unregisterExtendedRequest( oid );
            }
            // Extended responses
            for ( String oid : new ArrayList<>( ldapApiService.getExtendedResponseFactories().keySet() ) )
            {
                ldapApiService.unregisterExtendedResponse( oid );
            }
            // Intermediate responses
            for ( String oid : new ArrayList<>( ldapApiService.getIntermediateResponseFactories().keySet() ) )
            {
                ldapApiService.unregisterIntermediateResponse( oid );
            }
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
