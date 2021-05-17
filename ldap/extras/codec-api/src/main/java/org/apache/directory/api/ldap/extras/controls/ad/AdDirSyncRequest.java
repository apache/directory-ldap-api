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

import org.apache.directory.api.ldap.model.message.Control;


/**
 * The DirSync request control, as described in http://tools.ietf.org/html/draft-armijo-ldap-dirsync-00.
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
 *
 * <pre>
 * Client side :
 * realReplControlValue ::= SEQUENCE {
 *     parentsFirst            integer
 *     maxAttributeCount       integer
 *     cookie                  OCTET STRING
 * }
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 *
 */
public interface AdDirSyncRequest extends Control
{
    /** This control OID */
    String OID = "1.2.840.113556.1.4.841";

    /**
     * @return 1 if the parents of the children comes before their children
     */
    int getParentsFirst();


    /**
     * Tell the server that it should send the parents of the children before
     * their children.
     * NOTE: it should have been a boolean, it's an integer instead.
     *
     * @param parentsFirst When set to 1, will return the parents before children
     */
    void setParentsFirst( int parentsFirst );


    /**
     * @return The maximum attribute count to be returned
     */
    int getMaxAttributeCount();


    /**
     * @param maxAttributeCount The maximum attribute count to be returned
     */
    void setMaxAttributeCount( int maxAttributeCount );


    /**
     * @return The cookie used while processing the successive DirSync operations
     */
    byte[] getCookie();


    /**
     * @param cookie The cookie to send to the server. It's the value found in the response control. Should be null
     * for the first control.
     */
    void setCookie( byte[] cookie );
}
