/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.directory.api.ldap.model.message.controls;


import org.apache.directory.api.ldap.model.message.Control;


/**
 * Control which defines the Proxy Authorization request. More information is available in <a
 * href="https://tools.ietf.org/html/rfc4370">RFC 4370</a>. Below we have included section 3 of the RFC describing
 * this control:
 *
 * <pre>
 *  3. Proxy Authorization Control
 *
 *      A single Proxy Authorization Control may be included in any search,
 *   compare, modify, add, delete, or modify Distinguished Name (DN) or
 *   extended operation request message.  The exception is any extension
 *   that causes a change in authentication, authorization, or data
 *   confidentiality [RFC2829], such as Start TLS [LDAPTLS] as part of the
 *   controls field of the LDAPMessage, as defined in [RFC2251].
 *
 *   The controlType of the proxy authorization control is
 *   "2.16.840.1.113730.3.4.18".
 *
 *   The criticality MUST be present and MUST be TRUE.  This requirement
 *   protects clients from submitting a request that is executed with an
 *   unintended authorization identity.
 *
 *   Clients MUST include the criticality flag and MUST set it to TRUE.
 *   Servers MUST reject any request containing a Proxy Authorization
 *   Control without a criticality flag or with the flag set to FALSE with
 *   a protocolError error.  These requirements protect clients from
 *   submitting a request that is executed with an unintended
 *   authorization identity.
 *
 *   The controlValue SHALL be present and SHALL either contain an authzId
 *   [AUTH] representing the authorization identity for the request or be
 *   empty if an anonymous association is to be used.
 *
 *   The mechanism for determining proxy access rights is specific to the
 *   server's proxy authorization policy.
 *
 *   If the requested authorization identity is recognized by the server,
 *   and the client is authorized to adopt the requested authorization
 *   identity, the request will be executed as if submitted by the proxy
 *   authorization identity; otherwise, the result code 123 is returned.
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface ProxiedAuthz extends Control
{
    /** This control OID */
    String OID = "2.16.840.1.113730.3.4.18";


    /**
     * @return The authzId 
     */
    String getAuthzId();


    /**
     * @param authzId The authzId to set. Must be empty (not null), or a valid DN prefixed by 'dn:', or any
     * user information prefixed by 'u:'
     */
    void setAuthzId( String authzId );
}
