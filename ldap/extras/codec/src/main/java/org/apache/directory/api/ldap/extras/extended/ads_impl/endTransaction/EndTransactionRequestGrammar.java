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
package org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.BooleanDecoder;
import org.apache.directory.api.asn1.ber.tlv.BooleanDecoderException;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionRequestImpl;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.directory.api.asn1.ber.tlv.UniversalTag.BOOLEAN;
import static org.apache.directory.api.asn1.ber.tlv.UniversalTag.OCTET_STRING;
import static org.apache.directory.api.asn1.ber.tlv.UniversalTag.SEQUENCE;

/**
 * This class implements the EndTransactionRequest extended operation's ASN.1 grammar. 
 * All the actions are declared in this class. As it is a singleton, 
 * these declaration are only done once. The grammar is :
 * 
 * <pre>
 * txnEndReq ::= SEQUENCE {
 *         commit         BOOLEAN DEFAULT TRUE,
 *         identifier     OCTET STRING }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */

public class EndTransactionRequestGrammar extends AbstractGrammar<EndTransactionRequestContainer>
{

    /** logger */
    private static final Logger LOG = LoggerFactory.getLogger( EndTransactionRequestGrammar.class );

    /** Speedup for logs */
    static final boolean IS_DEBUG = LOG.isDebugEnabled();

    /** The instance of grammar. EndTransactionRequestGrammar is a singleton */
    private static Grammar<EndTransactionRequestContainer> instance = new EndTransactionRequestGrammar();


    /**
     * Creates a new EndTransactionRequestGrammar object.
     */
    @SuppressWarnings("unchecked")
    public EndTransactionRequestGrammar()
    {
        setName( EndTransactionRequestGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[EndTransactionRequestStates.LAST_STATE
            .ordinal()][256];

        /**
         * Transition from init state to EndTransactionRequest Sequence
         * 
         *  txnEndReq ::= SEQUENCE {
         *     ...
         *     
         * Creates the EndTransactionRequest object
         */
        super.transitions[EndTransactionRequestStates.START_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition<EndTransactionRequestContainer>(
                EndTransactionRequestStates.START_STATE,
                EndTransactionRequestStates.SEQUENCE_STATE,
                SEQUENCE, 
                new GrammarAction<EndTransactionRequestContainer>( "Init EndTransactionRequest" )
                {
                    public void action( EndTransactionRequestContainer container )
                    {
                        EndTransactionRequestDecorator endTransactionRequestDecorator = new EndTransactionRequestDecorator(
                            LdapApiServiceFactory.getSingleton(), new EndTransactionRequestImpl() );
                        container.setEndTransactionRequest( endTransactionRequestDecorator );
                    }
                } );

        /**
         * Transition from Sequence to commit flag
         *
         * txnEndReq ::= SEQUENCE {
         *         commit         BOOLEAN DEFAULT TRUE,
         *     ...
         *     
         * Set the commit flag into the EndTransactionRequest instance.
         */
        super.transitions[EndTransactionRequestStates.SEQUENCE_STATE.ordinal()][BOOLEAN.getValue()] =
            new GrammarTransition<EndTransactionRequestContainer>(
                EndTransactionRequestStates.SEQUENCE_STATE,
                EndTransactionRequestStates.COMMIT_STATE,
                BOOLEAN,
                new GrammarAction<EndTransactionRequestContainer>( "Set EndTransactionRequest commit flag" )
                {
                    public void action( EndTransactionRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            container.getEndTransactionRequest().setCommit( BooleanDecoder.parse( value ) );
                        }
                        catch ( BooleanDecoderException bde )
                        {
                            LOG.error( I18n
                                .err( I18n.ERR_04490_BAD_END_TRANSACTION_COMMIT, Strings.dumpBytes( value.getData() ), bde.getMessage() ) );

                            // This will generate a PROTOCOL_ERROR
                            throw new DecoderException( bde.getMessage(), bde );
                        }
                    }
                } );

        /**
         * Transition from Sequence to identifier
         *
         * txnEndReq ::= SEQUENCE {
         *         identifier     OCTET STRING }
         *     
         * Set the commit flag into the EndTransactionRequest instance.
         */
        super.transitions[EndTransactionRequestStates.SEQUENCE_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition<EndTransactionRequestContainer>(
                EndTransactionRequestStates.SEQUENCE_STATE,
                EndTransactionRequestStates.IDENTFIER_STATE,
                OCTET_STRING,
                new GrammarAction<EndTransactionRequestContainer>( "Set EndTransactionRequest identifier" )
                {
                    public void action( EndTransactionRequestContainer container )
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        byte[] identifier = value.getData();

                        if ( IS_DEBUG )
                        {
                            LOG.debug( "Identifier = {}", Strings.dumpBytes( identifier ) );
                        }

                        if ( identifier == null )
                        {
                            identifier = Strings.EMPTY_BYTES;
                        }

                        container.getEndTransactionRequest().setTransactionId( identifier );

                        // We may have nothing left
                        container.setGrammarEndAllowed( true );
                    }
                } );

        /**
         * Transition from commit flag to identifier
         *
         * txnEndReq ::= SEQUENCE {
         *         commit         BOOLEAN DEFAULT TRUE,
         *         identifier     OCTET STRING }
         *     
         * Set the identifier into the EndTransactionRequest instance.
         */
        super.transitions[EndTransactionRequestStates.COMMIT_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition<EndTransactionRequestContainer>(
                EndTransactionRequestStates.COMMIT_STATE,
                EndTransactionRequestStates.IDENTFIER_STATE,
                OCTET_STRING,
                new GrammarAction<EndTransactionRequestContainer>( "Set EndTransactionRequest identifier" )
                {
                    public void action( EndTransactionRequestContainer container )
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        byte[] identifier = value.getData();

                        if ( IS_DEBUG )
                        {
                            LOG.debug( "Identifier = {}", Strings.dumpBytes( identifier ) );
                        }

                        if ( identifier == null )
                        {
                            identifier = Strings.EMPTY_BYTES;
                        }

                        container.getEndTransactionRequest().setTransactionId( identifier );

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
    public static Grammar<EndTransactionRequestContainer> getInstance()
    {
        return instance;
    }
}
