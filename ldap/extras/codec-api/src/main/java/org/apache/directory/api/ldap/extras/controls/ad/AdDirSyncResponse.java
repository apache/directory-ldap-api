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
package org.apache.directory.api.ldap.extras.controls.ad;

import java.util.EnumSet;
import java.util.Set;

import org.apache.directory.api.ldap.model.message.Control;


/**
 * The DirSync response control, as described in http://tools.ietf.org/html/draft-armijo-ldap-dirsync-00.
 * Here is the ASN/1 description of the SearchRequest control :
 *
 * <pre>
 * Repl    Control ::= SEQUENCE {
 *     controlType             1.2.840.113556.1.4.841
 *     controlValue            replControlValue
 *     criticality             TRUE
 * }
 * </pre>
 *
 * the control value is :
 * <pre>
 * realReplControlValue ::= SEQUENCE {
 *     flag                  integer
 *     maxReturnLength       integer
 *     cookie                OCTET STRING
 * }
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 *
 */
public interface AdDirSyncResponse extends Control
{
    /** This control OID */
    String OID = "1.2.840.113556.1.4.841";

    /**
     * Get the maximum length of attributes
     * 
     * @return The maximum length of attributes to be returned
     */
    int getMaxReturnLength();


    /**
     * Set the maximum length of attributes
     * 
     * @param maxReturnLength The maximum length of attributes to be returned
     */
    void setMaxReturnLength( int maxReturnLength );


    /**
     * Get the cookie
     * 
     * @return The cookie used while processing the successive DirSync operations
     */
    byte[] getCookie();


    /**
     * Set the cookie
     * 
     * @param cookie The cookie to send to the server. It's the value found in the response control. Should be null
     * for the first control.
     */
    void setCookie( byte[] cookie );


    /**
     * Get the flags returned by the server. Zero or more of :
     * <ul>
     * <li>LDAP_DIRSYNC_OBJECT_SECURITY (0x0001)</li>
     * <li>LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER (0x0800)</li>
     * <li>LDAP_DIRSYNC_PUBLIC_DATA_ONLY (0x2000)(</li>
     * <li>LDAP_DIRSYNC_INCREMENTAL_VALUES (0x7FFFFFFF)</li>
     * </ul>
     * 
     * @return The flags 
     */
    Set<AdDirSyncResponseFlag> getFlags();


    /**
     * Set the flags 
     * 
     * @param flags The flags to be set. See {@link EnumSet} for how to generate EnumSets.
     */
    void setFlags( Set<AdDirSyncResponseFlag> flags );


    /**
     * Add a flag to the collection of flags
     * 
     * @param flag The flag to be added to the current collection of flags.
     */
    void addFlag( AdDirSyncResponseFlag flag );


    /**
     * Remove a given flag from the collection of flags
     * 
     * @param flag The flag to be removed from the current collection of flags.
     */
    void removeFlag( AdDirSyncResponseFlag flag );
}
