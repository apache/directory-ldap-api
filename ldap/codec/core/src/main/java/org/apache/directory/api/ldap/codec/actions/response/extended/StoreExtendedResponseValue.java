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
package org.apache.directory.api.ldap.codec.actions.response.extended;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainerDirect;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.OpaqueExtendedResponse;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store a Response to an ExtendedResponse
 * <pre>
 * ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
 *     ...
 *     response       [11] OCTET STRING OPTIONAL}
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoreExtendedResponseValue extends GrammarAction<LdapMessageContainerDirect<ExtendedResponse>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( StoreExtendedResponseValue.class );

    /**
     * Instantiates a new response action.
     */
    public StoreExtendedResponseValue()
    {
        super( "Store response value" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( LdapMessageContainerDirect<ExtendedResponse> container ) throws DecoderException
    {
        // We can allocate the ExtendedResponse Object
        ExtendedResponse extendedResponse = container.getMessage();

        // Get the Value and store it in the ExtendedResponse
        TLV tlv = container.getCurrentTLV();
        
        ExtendedOperationFactory factory = container.getExtendedFactory();

        // We have to handle the special case of a 0 length matched value
        try
        {
            if ( factory == null )
            {
                if ( tlv.getLength() == 0 )
                {
                    ( ( OpaqueExtendedResponse ) extendedResponse ).setResponseValue( Strings.EMPTY_BYTES );
                }
                else
                {
                    ( ( OpaqueExtendedResponse ) extendedResponse ).setResponseValue( tlv.getValue().getData() );
                }
            }
            else
            {
                factory.decodeValue( extendedResponse, tlv.getValue().getData() );
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
            LOG.debug( I18n.msg( I18n.MSG_05173_EXTENDED_VALUE, Strings.dumpBytes( tlv.getValue().getData() ) ) );
        }
    }
}
