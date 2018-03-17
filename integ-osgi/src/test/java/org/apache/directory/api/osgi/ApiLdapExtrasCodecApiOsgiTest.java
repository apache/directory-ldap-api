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
package org.apache.directory.api.osgi;


import org.apache.directory.api.ldap.extras.controls.SynchronizationModeEnum;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncImpl;
import org.apache.directory.api.ldap.extras.controls.ad.AdShowDeletedImpl;
import org.apache.directory.api.ldap.extras.controls.ad.AdPolicyHintsImpl;

import org.apache.directory.api.ldap.extras.controls.changeNotifications.ChangeNotificationsImpl;
import org.apache.directory.api.ldap.extras.controls.permissiveModify.PermissiveModifyImpl;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyImpl;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyResponseImpl;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncDone.SyncDoneValueImpl;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncRequest.SyncRequestValueImpl;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncState.SyncStateValueImpl;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequestImpl;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewResponseImpl
;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequestImpl;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyResponseImpl;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsRequestImpl;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsResponseImpl;
import org.apache.directory.api.ldap.extras.extended.startTransaction.StartTransactionRequestImpl;
import org.apache.directory.api.ldap.extras.extended.startTransaction.StartTransactionResponseImpl;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIRequestImpl;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIResponseImpl;
import org.apache.directory.api.ldap.extras.intermediate.syncrepl.SyncInfoValueImpl;
import org.apache.directory.api.ldap.model.name.Dn;


public class ApiLdapExtrasCodecApiOsgiTest extends ApiOsgiTestBase
{

    @Override
    protected String getBundleName()
    {
        return "org.apache.directory.api.ldap.extras.codec.api";
    }


    @Override
    protected void useBundleClasses() throws Exception
    {
        SynchronizationModeEnum.REFRESH_AND_PERSIST.getValue();
        new AdDirSyncImpl().getOid();
        new AdShowDeletedImpl().getOid();
        new AdPolicyHintsImpl().getOid();
        new ChangeNotificationsImpl().getOid();
        new PermissiveModifyImpl().getOid();
        new PasswordPolicyImpl().getOid();
        new PasswordPolicyResponseImpl().getGraceAuthNRemaining();
        new SyncDoneValueImpl().getOid();
        new SyncRequestValueImpl().getOid();
        new SyncStateValueImpl( true ).getCookie();
        new VirtualListViewRequestImpl().getOid();
        new VirtualListViewResponseImpl().getOid();
        new PasswordModifyRequestImpl().getUserIdentity();
        new PasswordModifyResponseImpl( 5 ).setResponseName( "foo" );
        new WhoAmIRequestImpl();
        new WhoAmIResponseImpl().setDn( new Dn( "uid=admin,ou=system" ) );
        new StartTlsRequestImpl();
        new StartTlsResponseImpl();
        new StartTransactionRequestImpl();
        new StartTransactionResponseImpl();
    }
}
