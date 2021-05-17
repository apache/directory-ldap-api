/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
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
import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store a Response Name to an ExtendedResponse
 * <pre>
 * LdapMessage ::= ... ExtendedResponse ...
 * ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
 *     COMPONENTS OF LDAPResult,
 *     responseName   [10] LDAPOID OPTIONAL,
 *     ...
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoreExtendedResponseName extends GrammarAction<LdapMessageContainer<ExtendedResponse>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( StoreExtendedResponseName.class );

    /**
     * Instantiates a new response name action.
     */
    public StoreExtendedResponseName()
    {
        super( "Store response name" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( LdapMessageContainer<ExtendedResponse> container ) throws DecoderException
    {
        // Get the Name and store it in the ExtendedResponse. That will
        // allow us to find the proper extended response instance, if it's 
        // already declared. Otherwise, we will use a default ExtendedResponse
        // in which the value will be stored un-decoded.
        TLV tlv = container.getCurrentTLV();

        // We have to handle the special case of a 0 length matched
        // OID
        if ( tlv.getLength() == 0 )
        {
            String msg = I18n.err( I18n.ERR_05122_NULL_NAME );
            LOG.error( msg );
            throw new DecoderException( msg );
        }
        else
        {
            byte[] responseNameBytes = tlv.getValue().getData();
            String responseName = Strings.asciiBytesToString( responseNameBytes );

            try
            {
                // Check the OID first, if it's invalid, reject the operation
                if ( !Oid.isOid( responseName ) )
                {
                    String msg = I18n.err( I18n.ERR_05159_INVALID_RESPONSE_NAME_OID,
                        responseName, Strings.dumpBytes( responseNameBytes ) );
                    LOG.error( msg );
    
                    // throw an exception, we will get a PROTOCOL_ERROR
                    throw new DecoderException( msg );
                }
    
                // Get the extended request factory from the LdapApiService, if it's registered
                LdapApiService codec = container.getLdapCodecService();
                ExtendedOperationFactory factory = codec.getExtendedResponseFactories().get( responseName );
                ExtendedResponse extendedResponse = container.getMessage();
                
                if ( factory != null )
                {
                    // Create the extended response
                    extendedResponse = factory.newResponse();

                    // Move the LDAPResult in the newly created response
                    LdapMessageContainer.copyLdapResult( container.getMessage(), extendedResponse );
                    extendedResponse.setMessageId( container.getMessageId() );
                    container.setMessage( extendedResponse );
                }
                else
                {
                   extendedResponse.setResponseName( responseName );
                }

                container.setExtendedFactory( factory );
                
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.msg( I18n.MSG_05172_OID_READ, extendedResponse.getResponseName() ) );
                }
            }
            catch ( DecoderException de )
            {
                String msg = I18n.err( I18n.ERR_05159_INVALID_RESPONSE_NAME_OID,
                    responseName, Strings.dumpBytes( responseNameBytes ) );
                LOG.error( I18n.err( I18n.ERR_05114_ERROR_MESSAGE, msg, de.getMessage() ) );

                // Rethrow the exception, we will get a PROTOCOL_ERROR
                throw de;
            }
        }

        // We can have an END transition
        container.setGrammarEndAllowed( true );
    }
}
