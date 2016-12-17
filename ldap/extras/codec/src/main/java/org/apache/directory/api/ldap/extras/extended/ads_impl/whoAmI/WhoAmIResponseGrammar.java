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
package org.apache.directory.api.ldap.extras.extended.ads_impl.whoAmI;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIResponseImpl;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements the WhoAmIResponse extended operation's ASN.1 grammer. 
 * All the actions are declared in this class. As it is a singleton, 
 * these declaration are only done once. The grammar is :
 * 
 * <pre>
 *  WhoAmIResponseValue ::= OCTET STRING OPTIONAL }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */

public class WhoAmIResponseGrammar extends AbstractGrammar<WhoAmIResponseContainer>
{
    /** logger */
    private static final Logger LOG = LoggerFactory.getLogger( WhoAmIResponseGrammar.class );

    /** Speedup for logs */
    static final boolean IS_DEBUG = LOG.isDebugEnabled();

    /** The instance of grammar. WhoAmIResponseGrammar is a singleton */
    private static Grammar<WhoAmIResponseContainer> instance = new WhoAmIResponseGrammar();


    /**
     * Creates a new WhoAmIResponseGrammar object.
     */
    @SuppressWarnings("unchecked")
    public WhoAmIResponseGrammar()
    {
        setName( WhoAmIResponseGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[WhoAmIResponseStatesEnum.LAST_WHO_AM_I_RESPONSE_STATE
            .ordinal()][256];

        /**
         * Transition from init state to WhoAmI Authzid Response Value
         * 
         * authzId ::= OCTET STRING OPTIONAL
         *     
         * Creates the authzid object
         */
        super.transitions[WhoAmIResponseStatesEnum.START_STATE.ordinal()][UniversalTag.OCTET_STRING.getValue()] =
            new GrammarTransition<WhoAmIResponseContainer>(
                WhoAmIResponseStatesEnum.START_STATE,
                WhoAmIResponseStatesEnum.AUTHZ_ID_RESPONSE_STATE,
                UniversalTag.OCTET_STRING.getValue(), new GrammarAction<WhoAmIResponseContainer>(
                    "Store AuthzId" )
                {
                    public void action( WhoAmIResponseContainer container ) throws DecoderException
                    {
                        WhoAmIResponseDecorator whoAmIResponse = new WhoAmIResponseDecorator(
                            LdapApiServiceFactory.getSingleton(), new WhoAmIResponseImpl() );
                        container.setWhoAmIResponse( whoAmIResponse );
                        
                        byte[] data = container.getCurrentTLV().getValue().getData();
                        
                        if ( data != null )
                        {
                            switch ( data.length )
                            {
                                case 0:
                                    // Error
                                case 1:
                                    // Error
                                    String msg = "authzId too short. Must starts with either u: or dn:";
                                    LOG.error( msg );
                                    throw new DecoderException( msg );

                                case 2 :
                                    if ( ( data[0] == 'u' ) && ( data[1] == ':' ) )
                                    {
                                        whoAmIResponse.setAuthzId( data );
                                        whoAmIResponse.setUserId( Strings.utf8ToString( data, 3, data.length - 3 ) );
                                    }
                                    else
                                    {
                                        msg = "authzId Must starts with either u: or dn:, it starts with " + Strings.utf8ToString( data );
                                        LOG.error( msg );
                                        throw new DecoderException( msg );
                                    }
                                    
                                    break;
                                    
                                default :
                                    switch ( data[0] )
                                    {
                                        case 'u' :
                                            if ( data[1] == ':' )
                                            {
                                                whoAmIResponse.setAuthzId( data );
                                                whoAmIResponse.setUserId( Strings.utf8ToString( data, 3, data.length - 3 ) );
                                            }
                                            else
                                            {
                                                msg = "authzId Must starts with either u: or dn:, it starts with " + Strings.utf8ToString( data );
                                                LOG.error( msg );
                                                throw new DecoderException( msg );
                                            }
                                            
                                            break;
                                            
                                        case 'd' :
                                            if ( ( data[1] == 'n' ) && ( data[2] == ':' ) )
                                            {
                                                // Check that the remaining bytes are a valid DN
                                                if ( Dn.isValid( Strings.utf8ToString( data, 3, data.length - 3 ) ) )
                                                {
                                                    whoAmIResponse.setAuthzId( data );
                                                    
                                                    try
                                                    {
                                                        whoAmIResponse.setDn( new Dn( Strings.utf8ToString( data, 3, data.length - 3 ) ) );
                                                    }
                                                    catch ( LdapInvalidDnException e )
                                                    {
                                                        // Should never happen
                                                    }
                                                }
                                                else
                                                {
                                                    msg = "authzId Must starts with either u: or dn:, it starts with " + Strings.utf8ToString( data );
                                                    LOG.error( msg );
                                                    throw new DecoderException( msg );
                                                }
                                            }
                                            else
                                            {
                                                msg = "authzId Must starts with either u: or dn:, it starts with " + Strings.utf8ToString( data );
                                                LOG.error( msg );
                                                throw new DecoderException( msg );
                                            }
                                            
                                            break;

                                        default :
                                            msg = "authzId Must starts with either u: or dn:, it starts with " + Strings.utf8ToString( data );
                                            LOG.error( msg );
                                            throw new DecoderException( msg );
                                    }
                                    
                                    break;
                            }
                        }
                        else
                        {
                            whoAmIResponse.setAuthzId( null );
                        }

                        // We may have nothing left
                        container.setGrammarEndAllowed( true );
                    }
                } );
    }


    /**
     * This class is a singleton.
     * 
     * @return An instance on this grammar
     */
    public static Grammar<WhoAmIResponseContainer> getInstance()
    {
        return instance;
    }
}
