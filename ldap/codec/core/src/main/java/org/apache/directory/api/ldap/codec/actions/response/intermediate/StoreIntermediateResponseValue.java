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
package org.apache.directory.api.ldap.codec.actions.response.intermediate;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.IntermediateOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainerDirect;
import org.apache.directory.api.ldap.model.message.IntermediateResponse;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store a IntermediateResponse value
 * <pre>
 * IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
 *     ...
 *     responseValue [1] OCTET STRING OPTIONAL
 *     }
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoreIntermediateResponseValue extends GrammarAction<LdapMessageContainerDirect<IntermediateResponse>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( StoreIntermediateResponseValue.class );

    /**
     * Instantiates a new response name action.
     */
    public StoreIntermediateResponseValue()
    {
        super( "Store response value" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( LdapMessageContainerDirect<IntermediateResponse> container ) throws DecoderException
    {
        // We can get the IntermediateResponse Object
        IntermediateResponse intermediateResponse = container.getMessage();

        // Get the Value and store it in the IntermediateResponse
        TLV tlv = container.getCurrentTLV();

        // We have to handle the special case of a 0 length matched
        // value
        if ( tlv.getLength() >= 0 )
        {
            // let's decode
            IntermediateOperationFactory intermediateFactory = container.getIntermediateFactory();
            
            if ( intermediateFactory != null )
            {
                intermediateFactory.decodeValue( intermediateResponse, tlv.getValue().getData() );
            }
            else
            {
                intermediateResponse.setResponseValue( tlv.getValue().getData() );
            }
        }

        // We can have an END transition
        container.setGrammarEndAllowed( true );

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_05175_VALUE_READ, Strings.dumpBytes( intermediateResponse.getResponseValue() ) ) );
        }
    }
}
