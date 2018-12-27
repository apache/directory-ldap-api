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
package org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction;


import java.nio.ByteBuffer;
import java.util.Iterator;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionRequest;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionRequestImpl;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionResponse;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionResponseImpl;
import org.apache.directory.api.ldap.extras.extended.endTransaction.UpdateControls;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;


/**
 * An {@link ExtendedOperationFactory} for creating EndTransaction extended request response 
 * pairs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EndTransactionFactory extends AbstractExtendedOperationFactory
{
    /**
     * Creates a new instance of EndTransactionFactory.
     *
     * @param codec The codec for this factory.
     */
    public EndTransactionFactory( LdapApiService codec )
    {
        super( codec, EndTransactionRequest.EXTENSION_OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EndTransactionRequest newRequest()
    {
        EndTransactionRequest endTransactionRequest = new EndTransactionRequestImpl();

        return endTransactionRequest;

    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EndTransactionRequest newRequest( byte[] encodedValue ) throws DecoderException
    {
        EndTransactionRequest endTransactionRequest = new EndTransactionRequestImpl();
        decodeValue( endTransactionRequest, encodedValue );

        return endTransactionRequest;

    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EndTransactionResponse newResponse()
    {
        EndTransactionResponse endTransactionResponse = new EndTransactionResponseImpl();

        return endTransactionResponse;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EndTransactionResponse newResponse( byte[] encodedValue ) throws DecoderException
    {
        EndTransactionResponse endTransactionResponse = new EndTransactionResponseImpl();
        decodeValue( endTransactionResponse, encodedValue );

        return endTransactionResponse;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( ExtendedRequest extendedRequest, byte[] requestValue ) throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.wrap( requestValue );
        EndTransactionRequestContainer container = new EndTransactionRequestContainer();
        container.setEndTransactionRequest( ( EndTransactionRequest ) extendedRequest ); 
        new Asn1Decoder().decode( bb, container );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( ExtendedResponse extendedResponse, byte[] requestValue ) throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.wrap( requestValue );
        EndTransactionResponseContainer container = new EndTransactionResponseContainer();
        container.setEndTransactionResponse( ( EndTransactionResponse ) extendedResponse ); 
        new Asn1Decoder().decode( bb, container );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, ExtendedRequest extendedRequest )
    {
        int start  = buffer.getPos();
        EndTransactionRequest transactionRequest = ( EndTransactionRequest ) extendedRequest;
        
        // The identifier
        BerValue.encodeOctetString( buffer, transactionRequest.getTransactionId() );
        
        // The commit flag, if false
        if ( !transactionRequest.getCommit() )
        {
            BerValue.encodeBoolean( buffer, false );
        }
        
        // The sequence
        BerValue.encodeSequence( buffer, start );
    }
    
    
    private void encodeControls( Asn1Buffer buffer, Iterator<Control> controls )
    {
        if ( controls.hasNext() )
        {
            Control control = controls.next();
            
            encodeControls( buffer, controls );

            int start = buffer.getPos();
            
            // The control value, if any
            ControlFactory<?> controlFactory = codec.getResponseControlFactories().get( control.getOid() );
            
            if ( controlFactory != null )
            {
                controlFactory.encodeValue( buffer, control );
                
                // The value sequence
                BerValue.encodeSequence( buffer, UniversalTag.OCTET_STRING.getValue(), start );
            }
            
            // The control criticality of TRUE
            if ( control.isCritical() )
            {
                BerValue.encodeBoolean( buffer, true );
            }
            
            // The control oid
            BerValue.encodeOctetString( buffer, control.getOid() );
            
            // The control sequence
            BerValue.encodeSequence( buffer, start );
        }
    } 
    
    
    private void encodeUpdatedControls( Asn1Buffer buffer, Iterator<UpdateControls> updateControls )
    {
        if ( updateControls.hasNext() )
        {
            UpdateControls updateControl = updateControls.next();
            
            encodeUpdatedControls( buffer, updateControls );

            int start = buffer.getPos();
            
            // The controls
            encodeControls( buffer, updateControl.getControls().iterator() );
            
            // The controls sequence
            BerValue.encodeSequence( buffer, start );
            
            // The messageID
            BerValue.encodeInteger( buffer, updateControl.getMessageId() );

            // The sequence
            BerValue.encodeSequence( buffer, start );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, ExtendedResponse extendedResponse )
    {
        int start  = buffer.getPos();
        EndTransactionResponse endTransactionResponse = ( EndTransactionResponse ) extendedResponse;
        
        // The controls
        if ( endTransactionResponse.getUpdateControls().size() > 0 )
        {
            encodeUpdatedControls( buffer, endTransactionResponse.getUpdateControls().iterator() );
            
            BerValue.encodeSequence( buffer, start );
        }
        
        // The messageID flag, if false
        if ( endTransactionResponse.getFailedMessageId() >= 0 )
        {
            BerValue.encodeInteger( buffer, endTransactionResponse.getFailedMessageId() );
        }
        
        // The sequence
        BerValue.encodeSequence( buffer, start );
    }
}
