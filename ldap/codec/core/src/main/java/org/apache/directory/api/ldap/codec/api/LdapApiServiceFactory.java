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


import org.apache.directory.api.i18n.I18n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A factory that allows callers a means to get a handle on an LdapCodecService
 * implementation regardless of the environment in which they're accessing it.
 * In an OSGi environment, the BundleActivator binds the LdapCodecService 
 * class member forever to the DefaultLdapCodecService. If in 
 * 
 * In a standard standalone mode, the Bundle
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class LdapApiServiceFactory
{
    /** Logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( LdapApiServiceFactory.class );

    /** The LdapCodecService singleton bound to this factory */
    private static LdapApiService ldapCodecService;

    /** Whether or not the standalone implementation is being used */
    private static boolean usingStandaloneImplementation;


    /**
     * Private constructor
     */
    private LdapApiServiceFactory()
    {
    }


    /**
     * Checks to see if the factory is initialized.
     *
     * @return true if initialized, false otherwise
     */
    public static boolean isInitialized()
    {
        return ldapCodecService != null;
    }


    /**
     * Checks to see if the factory is using the standalone implementation.
     *
     * @return true if using the standalone implementation, false otherwise.
     */
    public static boolean isUsingStandaloneImplementation()
    {
        if ( !isInitialized() )
        {
            String msg = I18n.err( I18n.ERR_05200_NOT_INITIALIZED_YET );
            LOG.error( msg );
            throw new IllegalStateException( msg );
        }

        return usingStandaloneImplementation;
    }


    /**
     * Gets the singleton instance of the LdapCodecService.
     *
     * @return a valid instance implementation based on environment and the 
     * availability of bindings.
     */
    public static LdapApiService getSingleton()
    {
        if ( ldapCodecService == null )
        {
            initialize( null );
        }

        return ldapCodecService;
    }


    /**
     * Initialization can only take place once. There after an exception 
     * results.
     * 
     * @param ldapCodecService The LDAP Codec Service to initialize with.
     */
    public static void initialize( LdapApiService ldapCodecService )
    {
        /*
         * If the class member is already set we have problems.
         */

        if ( LdapApiServiceFactory.ldapCodecService != null )
        {
            String msg = I18n.err( I18n.ERR_05201_INSTANCE_ALREADY_SET, LdapApiServiceFactory.class.getName() );
            LOG.error( msg );
            throw new IllegalStateException( msg );
        }

        /*
         * If the argument is null, then we attempt discovery
         */

        if ( ldapCodecService == null )
        {
            try
            {
                @SuppressWarnings("unchecked")
                Class<? extends LdapApiService> serviceClass = ( Class<? extends LdapApiService> )
                    Class.forName( "org.apache.directory.api.ldap.codec.standalone.StandaloneLdapApiService" );
                LdapApiServiceFactory.ldapCodecService = serviceClass.newInstance();
                usingStandaloneImplementation = true;
            }
            catch ( Exception e )
            {
                LOG.error( I18n.err( I18n.ERR_05202_FAILED_TO_INSTANCIATE, e.getMessage() ) );
            }
        }
        else
        {
            usingStandaloneImplementation = false;
            LdapApiServiceFactory.ldapCodecService = ldapCodecService;
        }
    }
}
