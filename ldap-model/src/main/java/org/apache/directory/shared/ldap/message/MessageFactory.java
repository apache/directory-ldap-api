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
package org.apache.directory.shared.ldap.message;


/**
 * Interface for a factory that creates LDAP request response message instances.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface MessageFactory
{
    Response newResponse( SingleReplyRequest request );

    AbandonRequest newAbandonRequest( int id );

    AddRequest newAddRequest( int id );

    BindRequest newBindRequest( int id );

    BindResponse newBindResponse( int id );

    CompareRequest newCompareRequest( int id );

    DeleteRequest newDeleteRequest( int id );

    ExtendedRequest newExtendedRequest( int id );

    ModifyDnRequest newModifyDnRequest( int id );

    ModifyRequest newModifyRequest( int id );

    SearchRequest newSearchRequest( int id );

    UnbindRequest newUnbindRequest( int id );

    SearchResultDone newSearchResultDone( int id );

    SearchResultEntry newSearchResultEntry( int id );

    SearchResultReference newSearchResultReference( int id );

    Referral newReferral();
}
