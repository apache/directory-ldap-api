/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.directory.api.ldap.extras.controls.syncrepl.syncDone;


import org.apache.directory.api.ldap.model.message.Control;


/**
 * A syncDoneValue object as described in rfc4533 :
 *
 * <pre>
 * 2.4.  Sync Done Control
 *
 *    The Sync Done Control is an LDAP Control [RFC4511] where the
 *    controlType is the object identifier 1.3.6.1.4.1.4203.1.9.1.3 and the
 *    controlValue contains a BER-encoded syncDoneValue.  The criticality
 *    is FALSE (and hence absent).
 *
 *       syncDoneValue ::= SEQUENCE {
 *           cookie          syncCookie OPTIONAL,
 *           refreshDeletes  BOOLEAN DEFAULT FALSE
 *       }
 *
 *    The Sync Done Control is only applicable to the SearchResultDone
 *    Message.
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface SyncDoneValue extends Control
{
    /** This control OID */
    String OID = "1.3.6.1.4.1.4203.1.9.1.3";


    /**
     * get the cookie
     * 
     * @return the cookie
     */
    byte[] getCookie();


    /**
     * Set the cookie
     * 
     * @param cookie cookie to be set
     */
    void setCookie( byte[] cookie );


    /**
     * Tells if the refreshDeletes flag is set to <code>true</code>
     * @return <code>true</code>, if refreshDeletes flag is set, <code>false</code> otherwise
     */
    boolean isRefreshDeletes();


    /**
     * Set the refreshDeletes flag
     * 
     * @param refreshDeletes set the refreshDeletes flag
     */
    void setRefreshDeletes( boolean refreshDeletes );
}
