/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
 * The AdPolicyHints control, an Active Directory control. Its syntax is :
 * 
 * <pre>
 * PolicyHintsRequestValue ::= SEQUENCE {
 *       Flags    INTEGER
 *   }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface AdPolicyHints extends Control
{
    /** This control OID */
    String OID = "1.2.840.113556.1.4.2239";

    /**
     * @return The flags
     */
    int getFlags();


    /**
     * Set the flags in the control.
     * 
     * @param flags The flags to set.
     */
    void setFlags( int flags );
} 