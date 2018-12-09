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
package org.apache.directory.api.ldap.extras.extended.ads_impl.storedProcedure;


import java.util.Iterator;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureParameter;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureRequest;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureResponse;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureResponseImpl;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;


/**
 * An {@link ExtendedOperationFactory} for creating cancel extended request response 
 * pairs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoredProcedureFactory extends AbstractExtendedOperationFactory
{
    /**
     * Creates a new instance of StoredProcedureFactory.
     *
     * @param codec The LDAP Service to use
     */
    public StoredProcedureFactory( LdapApiService codec )
    {
        super( codec );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return StoredProcedureRequest.EXTENSION_OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StoredProcedureResponse newResponse( byte[] encodedValue ) throws DecoderException
    {
        StoredProcedureResponseDecorator response = new StoredProcedureResponseDecorator( codec,
            new StoredProcedureResponseImpl() );
        response.setResponseValue( encodedValue );
        return response;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StoredProcedureRequest newRequest( byte[] value )
    {
        StoredProcedureRequestDecorator req = new StoredProcedureRequestDecorator( codec );

        if ( value != null )
        {
            req.setRequestValue( value );
        }
        return req;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StoredProcedureRequestDecorator decorate( ExtendedRequest modelRequest )
    {
        if ( modelRequest instanceof StoredProcedureRequestDecorator )
        {
            return ( StoredProcedureRequestDecorator ) modelRequest;
        }

        return new StoredProcedureRequestDecorator( codec, ( StoredProcedureRequest ) modelRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StoredProcedureResponseDecorator decorate( ExtendedResponse decoratedMessage )
    {
        if ( decoratedMessage instanceof StoredProcedureResponseDecorator )
        {
            return ( StoredProcedureResponseDecorator ) decoratedMessage;
        }

        return new StoredProcedureResponseDecorator( codec, ( StoredProcedureResponse ) decoratedMessage );
    }
    
    
    private void encodeParameters( Asn1Buffer buffer, Iterator<StoredProcedureParameter> parameters )
    {
        if ( parameters.hasNext() )
        {
            StoredProcedureParameter parameter = parameters.next();
            
            encodeParameters( buffer, parameters );
            
            int start = buffer.getPos();
            
            // The value
            BerValue.encodeOctetString( buffer, parameter.getValue() );
            
            // The type
            BerValue.encodeOctetString( buffer, parameter.getType() );
            
            // The parameter sequence
            BerValue.encodeSequence( buffer, start );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, ExtendedRequest extendedRequest )
    {
        int start  = buffer.getPos();
        
        StoredProcedureRequest storedProcedureRequest = ( StoredProcedureRequest ) extendedRequest; 
        
        encodeParameters( buffer, storedProcedureRequest.getParameters().iterator() );
        
        // The parameters sequence
        BerValue.encodeSequence( buffer, start );
        
        // The procedure
        BerValue.encodeOctetString( buffer, storedProcedureRequest.getProcedure() );

        // The language
        BerValue.encodeOctetString( buffer, storedProcedureRequest.getLanguage() );
        
        // The sequence
        BerValue.encodeSequence( buffer, start );
    }
}
