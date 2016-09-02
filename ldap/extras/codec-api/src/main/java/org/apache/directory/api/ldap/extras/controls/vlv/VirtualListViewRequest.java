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
 * Virtual List View control as specified in draft-ietf-ldapext-ldapv3-vlv-09.
 * 
 *  VirtualListViewRequest ::= SEQUENCE {
 *         beforeCount    INTEGER (0..maxInt),
 *         afterCount     INTEGER (0..maxInt),
 *         target       CHOICE {
 *                        byOffset        [0] SEQUENCE {
 *                             offset          INTEGER (1 .. maxInt),
 *                             contentCount    INTEGER (0 .. maxInt) },
 *                        greaterThanOrEqual [1] AssertionValue },
 *         contextID     OCTET STRING OPTIONAL }
 * 
 * Note : the target is set accordingly to which of the setOffset() or
 * assertionValue() method is called last.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface VirtualListViewRequest extends Control
{
    /** This control OID */
    String OID = "2.16.840.1.113730.3.4.9";


    /**
     * @return The number of entries before the target entry that are going to be sent
     */
    int getBeforeCount();


    /**
     * @param beforeCount Set the number of entries to be returned before the target entry
     */
    void setBeforeCount( int beforeCount );


    /**
     * @return The number of entries after the target entry that are going to be sent
     */
    int getAfterCount();


    /**
     * @param afterCount Set the number of entries to be returned after the target entry
     */
    void setAfterCount( int afterCount );


    /**
     * @return The position of the target entry
     */
    int getOffset();


    /**
     * @param offset the position of the target entry
     */
    void setOffset( int offset );


    /**
     * @return The number of expected entries
     */
    int getContentCount();


    /**
     * @param contentCount The number of entries
     */
    void setContentCount( int contentCount );


    /**
     * @return The AssertionValue
     */
    byte[] getAssertionValue();


    /**
     * @param assertionValue Set the AssertionValue
     */
    void setAssertionValue( byte[] assertionValue );


    /**
     * @return The ID used for this request
     */
    byte[] getContextId();


    /**
     * @param contextId Set the context ID
     */
    void setContextId( byte[] contextId );


    /**
     * @return <code>true</code> if the VLV target is an offset, false otherwise
     */
    boolean hasOffset();


    /**
     * @return <code>true</code> if the VLV target is an assertionValue, false otherwise
     */
    boolean hasAssertionValue();
}
