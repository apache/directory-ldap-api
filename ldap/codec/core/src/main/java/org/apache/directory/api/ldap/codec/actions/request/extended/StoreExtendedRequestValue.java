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
package org.apache.directory.api.ldap.codec.actions.request.extended;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.OpaqueExtendedRequest;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store the Extended Request value
 * <pre>
 * ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
 *     ...
 *     requestValue  [1] OCTET STRING OPTIONAL }
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoreExtendedRequestValue extends GrammarAction<LdapMessageContainer<ExtendedRequest>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( StoreExtendedRequestValue.class );

    /**
     * Instantiates a new action.
     */
    public StoreExtendedRequestValue()
    {
        super( "Store ExtendedRequest value" );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void action( LdapMessageContainer<ExtendedRequest> container ) throws DecoderException
    {
        // We can allocate the ExtendedRequest Object
        ExtendedRequest extendedRequest = container.getMessage();

        // Get the Value and store it in the ExtendedRequest
        TLV tlv = container.getCurrentTLV();
        
        ExtendedOperationFactory factory = container.getLdapCodecService().
            getExtendedRequestFactories().get( extendedRequest.getRequestName() );

        // We have to handle the special case of a 0 length matched
        // value
        try
        {
            if ( factory == null )
            {
                if ( tlv.getLength() == 0 )
                {
                    ( ( OpaqueExtendedRequest ) extendedRequest ).setRequestValue( Strings.EMPTY_BYTES );
                } 
                else
                {
                    ( ( OpaqueExtendedRequest ) extendedRequest ).setRequestValue( tlv.getValue().getData() );
                }
            }
            else
            {
                factory.decodeValue( extendedRequest, tlv.getValue().getData() );
            }
        }
        catch ( DecoderException de )
        {
            String msg = I18n.err( I18n.ERR_05158_INVALID_REQUEST_VALUE,
                Strings.dumpBytes( tlv.getValue().getData() ) );
            LOG.error( I18n.err( I18n.ERR_05114_ERROR_MESSAGE, msg, de.getMessage() ) );

            // Rethrow the exception, we will get a PROTOCOL_ERROR
            throw de;
        }

        // We can have an END transition
        container.setGrammarEndAllowed( true );

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_05127_EXTENDED_VALUE, 
                Strings.dumpBytes( tlv.getValue().getData() ) ) );
        }
    }
}
