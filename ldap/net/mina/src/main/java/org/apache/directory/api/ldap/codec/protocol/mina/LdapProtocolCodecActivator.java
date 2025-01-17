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
package org.apache.directory.api.ldap.codec.protocol.mina;


import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.util.tracker.ServiceTracker;
import org.osgi.util.tracker.ServiceTrackerCustomizer;


/**
 * The {@link org.osgi.framework.BundleActivator} for the codec.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapProtocolCodecActivator implements BundleActivator
{
    /** The LDapApi service tracker */
    private ServiceTracker<LdapApiService, LdapApiService> serviceTracker;

    /**
     * A class used to track the LdapApi service
     * 
     */
    class LdapApiServiceTracker implements ServiceTrackerCustomizer<LdapApiService, LdapApiService>
    {
        /** The Bundle Context instance */
        private BundleContext bundleContext;
        
        /** The Serviceregistration instance */
        private ServiceRegistration<?> registration;


        /**
         * Create a LdapApiServiceTracker instance with a context
         * 
         * @param context The BundleContext for this instance
         */
        LdapApiServiceTracker( BundleContext context )
        {
            this.bundleContext = context;
        }


        /**
         * {@inheritDoc}
         */
        @Override
        public LdapApiService addingService( ServiceReference<LdapApiService> reference )
        {
            LdapApiService ldapApiService = bundleContext.getService( reference );
            LdapProtocolCodecFactory factory = new LdapProtocolCodecFactory( ldapApiService );
            registration = bundleContext.registerService( LdapProtocolCodecFactory.class.getName(), factory, null );
            ldapApiService.registerProtocolCodecFactory( factory );
            return ldapApiService;
        }


        /**
         * {@inheritDoc}
         */
        @Override
        public void modifiedService( ServiceReference<LdapApiService> reference, LdapApiService service )
        {
            // Do nothing ATM
        }


        /**
         * {@inheritDoc}
         */
        @Override
        public void removedService( ServiceReference<LdapApiService> reference, LdapApiService service )
        {
            // TODO should we unregister the LdapProtocolCodecFactory at LdapApiService?
            // ldapApiService.unregisterProtocolCodecFactory( factory );
            registration.unregister();
        }
    }


    /**
     * Create a new instance of a LdapProtocolCodecActivator 
     */
    public LdapProtocolCodecActivator()
    {
        // Default constructor
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void start( BundleContext bundleContext ) throws Exception
    {
        LdapApiServiceTracker ldapApiServiceTracker = new LdapApiServiceTracker( bundleContext );
        serviceTracker = new ServiceTracker<>( bundleContext, LdapApiService.class,
            ldapApiServiceTracker );
        serviceTracker.open();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void stop( BundleContext bundleContext ) throws Exception
    {
        serviceTracker.close();
    }
}
