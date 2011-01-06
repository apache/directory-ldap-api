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
package org.apache.directory.shared.ldap.codec.message;


import org.apache.directory.shared.ldap.message.*;


/**
 * A MessageFactory implemented by the Codec to hide implementation details.
 *
 * @author <a href="mailto:dev@directory.apache.org"> Apache Directory Project</a>
 *         $Rev: 946353 $
 */
public class CodecMessageFactory implements MessageFactory
{
    public Response newResponse( SingleReplyRequest request )
    {
        Response response = null;

        switch ( request.getResponseType() )
        {
            case ADD_REQUEST:
                response = new AddResponseImpl( request.getMessageId() );
                break;
            case BIND_REQUEST:
                response = new BindResponseImpl( request.getMessageId() );
                break;
            case COMPARE_REQUEST:
                response = new CompareResponseImpl( request.getMessageId() );
                break;
            case DEL_REQUEST:
                response = new DeleteResponseImpl( request.getMessageId() );
                break;
            case EXTENDED_REQUEST:
                response = new ExtendedResponseImpl( request.getMessageId() );
                break;
            case MODIFYDN_RESPONSE:
                response = new ModifyDnResponseImpl( request.getMessageId() );
                break;
            case MODIFY_REQUEST:
                response = new ModifyResponseImpl( request.getMessageId() );
                break;
            default:
                throw new IllegalArgumentException( "Not a SingleReplyRequest instance: " + request.getResponseType() );
        }

        return response;
    }


    public AbandonRequest newAbandonRequest( int id )
    {
        return new AbandonRequestImpl( id );
    }


    public AddRequest newAddRequest( int id )
    {
        return new AddRequestImpl( id );
    }


    public BindRequest newBindRequest( int id )
    {
        return new BindRequestImpl( id );
    }


    public BindResponse newBindResponse( int id )
    {
        return new BindResponseImpl( id );
    }


    public CompareRequest newCompareRequest( int id )
    {
        return new CompareRequestImpl( id );
    }


    public DeleteRequest newDeleteRequest( int id )
    {
        return new DeleteRequestImpl( id );
    }


    public ExtendedRequest newExtendedRequest( int id )
    {
        return new ExtendedRequestImpl( id );
    }


    public ModifyDnRequest newModifyDnRequest( int id )
    {
        return new ModifyDnRequestImpl( id );
    }


    public ModifyRequest newModifyRequest( int id )
    {
        return new ModifyRequestImpl( id );
    }


    public SearchRequest newSearchRequest( int id )
    {
        return new SearchRequestImpl( id );
    }


    public UnbindRequest newUnbindRequest( int id )
    {
        return new UnbindRequestImpl( id );
    }


    public SearchResultDone newSearchResultDone( int id )
    {
        return new SearchResultDoneImpl( id );
    }


    public SearchResultEntry newSearchResultEntry( int id )
    {
        return new SearchResultEntryImpl( id );
    }


    public SearchResultReference newSearchResultReference( int id )
    {
        return new SearchResultReferenceImpl( id );
    }


    public Referral newReferral()
    {
        return new ReferralImpl();
    }
}
