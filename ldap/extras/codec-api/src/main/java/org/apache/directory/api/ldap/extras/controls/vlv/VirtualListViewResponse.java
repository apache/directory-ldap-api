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

package org.apache.directory.api.ldap.extras.controls.vlv;


import org.apache.directory.api.ldap.model.message.Control;


/**
 * Virtual List View response control as specified in draft-ietf-ldapext-ldapv3-vlv-09.
 * <pre>
 *  VirtualListViewResponse ::= SEQUENCE {
 *         targetPosition    INTEGER (0 .. maxInt),
 *         contentCount     INTEGER (0 .. maxInt),
 *         virtualListViewResult ENUMERATED {
 *              success (0),
 *              operationsError (1),
 *              protocolError (3),
 *              unwillingToPerform (53),
 *              insufficientAccessRights (50),
 *              timeLimitExceeded (3),
 *              adminLimitExceeded (11),
 *              innapropriateMatching (18),
 *              sortControlMissing (60),
 *              offsetRangeError (61),
 *              other(80),
 *              ... 
 *         },
 *         contextID     OCTET STRING OPTIONAL 
 * }
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface VirtualListViewResponse extends Control
{
    /** the OID of the response control */
    String OID = "2.16.840.1.113730.3.4.10";


    int getTargetPosition();


    void setTargetPosition( int targetPosition );


    int getContentCount();


    void setContentCount( int contentCount );


    VirtualListViewResultCode getVirtualListViewResult();


    void setVirtualListViewResult( VirtualListViewResultCode virtualListViewResultCode );


    byte[] getContextId();


    void setContextId( byte[] contextId );
}
