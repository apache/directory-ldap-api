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
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
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
import org.apache.directory.api.ldap.extras.extended.ads_impl.cancel.CancelFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.certGeneration.CertGenerationFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulDisconnect.GracefulDisconnectFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulShutdown.GracefulShutdownFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify.PasswordModifyFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.storedProcedure.StoredProcedureFactory;
import org.apache.directory.api.ldap.extras.extended.cancel.CancelRequest;
import org.apache.directory.api.ldap.extras.extended.certGeneration.CertGenerationRequest;
import org.apache.directory.api.ldap.extras.extended.gracefulDisconnect.GracefulDisconnectResponse;
import org.apache.directory.api.ldap.extras.extended.gracefulShutdown.GracefulShutdownRequest;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureRequest;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;


/**
 * A BundleActivator for the ldap codec extras extension: extra ApacheDS and 
 * Apache Directory Studio specific controls and extended operations. 
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ExtrasBundleActivator implements BundleActivator
{
    private ServiceReference<?> codecServiceRef;


    /**
     * {@inheritDoc}
     */
    public void start( BundleContext context ) throws Exception
    {
        codecServiceRef = context.getServiceReference( LdapApiService.class.getName() );
        LdapApiService codec = ( LdapApiService ) context.getService( codecServiceRef );
        registerExtrasControls( codec );
        registerExtrasExtendedOps( codec );
    }


    /**
     * Registers all the extras controls present in this control pack.
     *
     * @param codec The codec service.
     */
    private void registerExtrasControls( LdapApiService codec )
    {
        ControlFactory<SyncDoneValue> syncDoneValuefactory = new SyncDoneValueFactory( codec );
        codec.registerControl( syncDoneValuefactory );

        ControlFactory<SyncInfoValue> syncInfoValueFactory = new SyncInfoValueFactory( codec );
        codec.registerControl( syncInfoValueFactory );

        ControlFactory<SyncRequestValue> syncRequestValueFactory = new SyncRequestValueFactory( codec );
        codec.registerControl( syncRequestValueFactory );

        ControlFactory<SyncStateValue> syncStateValuefactory = new SyncStateValueFactory( codec );
        codec.registerControl( syncStateValuefactory );

        ControlFactory<PasswordPolicy> passwordPolicyFactory = new PasswordPolicyFactory( codec );
        codec.registerControl( passwordPolicyFactory );
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

        ExtendedOperationFactory<?, ?> extReqfactory = new CancelFactory( codec );
        codec.registerExtendedRequest( extReqfactory );

        extReqfactory = new CertGenerationFactory( codec );
        codec.registerExtendedRequest( extReqfactory );

        extReqfactory = new GracefulShutdownFactory( codec );
        codec.registerExtendedRequest( extReqfactory );

        extReqfactory = new StoredProcedureFactory( codec );
        codec.registerExtendedRequest( extReqfactory );

        extReqfactory = new PasswordModifyFactory( codec );
        codec.registerExtendedRequest( extReqfactory );

        extReqfactory = new GracefulDisconnectFactory( codec );
        codec.registerExtendedRequest( extReqfactory );
    }


    /**
     * {@inheritDoc}
     */
    public void stop( BundleContext context ) throws Exception
    {
        LdapApiService codec = ( LdapApiService ) context.getService( codecServiceRef );

        codec.unregisterControl( SyncDoneValue.OID );
        codec.unregisterControl( SyncInfoValue.OID );
        codec.unregisterControl( SyncRequestValue.OID );
        codec.unregisterControl( SyncStateValue.OID );
        codec.unregisterControl( PasswordPolicy.OID );

        codec.unregisterExtendedRequest( CancelRequest.EXTENSION_OID );
        codec.unregisterExtendedRequest( CertGenerationRequest.EXTENSION_OID );
        codec.unregisterExtendedRequest( GracefulShutdownRequest.EXTENSION_OID );
        codec.unregisterExtendedRequest( StoredProcedureRequest.EXTENSION_OID );
        codec.unregisterExtendedRequest( GracefulDisconnectResponse.EXTENSION_OID );
    }
}
