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
package org.apache.directory.api.ldap.extras.controls.relax;


import org.apache.directory.api.ldap.model.message.Control;

/**
 * The Relax {@link Control} interface.
 * The LDAP Relax Rules Control. It's defined in https://tools.ietf.org/html/draft-zeilenga-ldap-relax-03.
 * This control is sent with every update of pwdPolicySubEntry, pwdAccountLockedTime and pwdReset on user entry.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public interface RelaxControl extends Control
{
    /** The LDAP Relax Rules Control OID */
    String OID = "1.3.6.1.4.1.4203.666.5.12";
}
