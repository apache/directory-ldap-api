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


import static org.apache.directory.api.asn1.ber.tlv.UniversalTag.SEQUENCE;

import java.util.List;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoder;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoderException;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionResponseImpl;
import org.apache.directory.api.ldap.extras.extended.endTransaction.UpdateControls;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.directory.api.asn1.ber.tlv.UniversalTag.INTEGER;

/**
 * This class implements the EndTransactionResponse extended operation's ASN.1 grammar. 
 * All the actions are declared in this class. As it is a singleton, 
 * these declaration are only done once. The grammar is :
 * 
 * <pre>
 * txnEndRes ::= SEQUENCE {
 *         messageID MessageID OPTIONAL,
 *              -- msgid associated with non-success resultCode
 *         updatesControls SEQUENCE OF updateControl SEQUENCE {
 *              messageID MessageID,
 *                   -- msgid associated with controls
 *              controls  Controls
 *         } OPTIONAL
 *    }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EndTransactionResponseGrammar extends AbstractGrammar<EndTransactionResponseContainer>
{
    /** logger */
    private static final Logger LOG = LoggerFactory.getLogger( EndTransactionResponseGrammar.class );

    /** Speedup for logs */
    static final boolean IS_DEBUG = LOG.isDebugEnabled();

    /** The instance of grammar. EndTransactionResponseGrammar is a singleton */
    private static Grammar<EndTransactionResponseContainer> instance = new EndTransactionResponseGrammar();


    /**
     * Creates a new EndTransactionResponseGrammar object.
     */
    @SuppressWarnings("unchecked")
    public EndTransactionResponseGrammar()
    {
        setName( EndTransactionResponseGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[EndTransactionResponseStates.LAST_STATE
            .ordinal()][256];

        /**
         * Transition from init state to EndTransactionResponse Sequence
         * 
         *  txnEndRes ::= SEQUENCE {
         *     ...
         *     
         * Creates the EndTransactionResponse object
         */
        super.transitions[EndTransactionResponseStates.START_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition<EndTransactionResponseContainer>(
                EndTransactionResponseStates.START_STATE,
                EndTransactionResponseStates.END_TRANSACTION_SEQUENCE_STATE,
                SEQUENCE, 
                new GrammarAction<EndTransactionResponseContainer>( "Init EndTransactionResponse" )
                {
                    public void action( EndTransactionResponseContainer container )
                    {
                        // Create the decorator, and stores it in the container
                        EndTransactionResponseDecorator endTransactionResponseDecorator = new EndTransactionResponseDecorator(
                            LdapApiServiceFactory.getSingleton(), new EndTransactionResponseImpl() );
                        container.setEndTransactionResponse( endTransactionResponseDecorator );
                    }
                } );

        /**
         * Transition from Sequence to messageId
         *
         * txnEndReq ::= SEQUENCE {
         *         messageID MessageID OPTIONAL,
         *              -- msgid associated with non-success resultCode
         *     ...
         *     
         * Set the messageId into the EndTransactionResponse instance, if it's not SUCCESS.
         */
        super.transitions[EndTransactionResponseStates.END_TRANSACTION_SEQUENCE_STATE.ordinal()][INTEGER.getValue()] =
            new GrammarTransition<EndTransactionResponseContainer>(
                EndTransactionResponseStates.END_TRANSACTION_SEQUENCE_STATE,
                EndTransactionResponseStates.FAILED_MESSAGE_ID_STATE,
                INTEGER,
                new GrammarAction<EndTransactionResponseContainer>( "Set EndTransactionResponse failed MessageID" )
                {
                    public void action( EndTransactionResponseContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            int failedMessageId = IntegerDecoder.parse( value );
                            
                            if ( failedMessageId > 0 )
                            {
                                container.getEndTransactionResponse().setFailedMessageId( failedMessageId );
                            }

                            // We may have nothing left
                            container.setGrammarEndAllowed( true );
                        }
                        catch ( IntegerDecoderException ide )
                        {
                            LOG.error( I18n
                                .err( I18n.ERR_04490_BAD_END_TRANSACTION_COMMIT, Strings.dumpBytes( value.getData() ), ide.getMessage() ) );

                            // This will generate a PROTOCOL_ERROR
                            throw new DecoderException( ide.getMessage(), ide );
                        }
                    }
                } );

        
        /**
         * Transition from Sequence to updateControls
         *
         * txnEndReq ::= SEQUENCE {
         *                  ...
         *                  updatesControls SEQUENCE OF updateControls SEQUENCE {
         *     
         * Nothing to do, just transitionning
         */
        super.transitions[EndTransactionResponseStates.END_TRANSACTION_SEQUENCE_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition<EndTransactionResponseContainer>(
                EndTransactionResponseStates.END_TRANSACTION_SEQUENCE_STATE,
                EndTransactionResponseStates.UPDATE_CONTROLS_SEQ_STATE,
                SEQUENCE );

        
        /**
         * Transition from updateControls to updateControl
         *
         * txnEndReq ::= SEQUENCE {
         *                  ...updateControls SEQUENCE {
         *     
         * Create a new UpdateControls instane
         */
        super.transitions[EndTransactionResponseStates.UPDATE_CONTROLS_SEQ_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition<EndTransactionResponseContainer>(
                EndTransactionResponseStates.UPDATE_CONTROLS_SEQ_STATE,
                EndTransactionResponseStates.UPDATE_CONTROL_SEQ_STATE,
                SEQUENCE,
                new GrammarAction<EndTransactionResponseContainer>( "Create an updateControl" )
                {
                    public void action( EndTransactionResponseContainer container )
                    {
                        // Create the current UpdateControls
                        UpdateControls currentUpdateControls = new UpdateControls();
                        
                        container.getEndTransactionResponse().setCurrentControls( currentUpdateControls );
                    }
                } );

        
        /**
         * Transition from updateControl to messageId
         *
         * txnEndReq ::= SEQUENCE {
         *                  ...
         *                  messageID MessageID,
         *     
         * Set the messageId into the current updateControl
         */
        super.transitions[EndTransactionResponseStates.UPDATE_CONTROL_SEQ_STATE.ordinal()][INTEGER.getValue()] =
            new GrammarTransition<EndTransactionResponseContainer>(
                EndTransactionResponseStates.UPDATE_CONTROL_SEQ_STATE,
                EndTransactionResponseStates.CONTROL_MESSAGE_ID_STATE,
                INTEGER,
                new GrammarAction<EndTransactionResponseContainer>( "Get the updateControl messageId" )
                {
                    public void action( EndTransactionResponseContainer container ) throws DecoderException
                    {
                        UpdateControls currentUpdateControls = container.getEndTransactionResponse().getCurrentUpdateControls();
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            int messageId = IntegerDecoder.parse( value );
                            
                            currentUpdateControls.setMessageId( messageId );
                            
                            // Make the container gather the following bytes
                            container.setGathering( true );
                        }
                        catch ( IntegerDecoderException ide )
                        {
                            LOG.error( I18n
                                .err( I18n.ERR_04491_BAD_END_TRANSACTION_MESSAGE_ID, Strings.dumpBytes( value.getData() ), 
                                    ide.getMessage() ) );

                            // This will generate a PROTOCOL_ERROR
                            throw new DecoderException( ide.getMessage(), ide );
                        }
                    }
                } );
        
        
        /**
         * ...
         *              messageID MessageID,
         *                   -- msgid associated with controls
         *              controls  Controls
         *  ...
         *
         * Process the controls
         */
        super.transitions[EndTransactionResponseStates.CONTROL_MESSAGE_ID_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition<EndTransactionResponseContainer>(
                EndTransactionResponseStates.CONTROL_MESSAGE_ID_STATE,
                EndTransactionResponseStates.CONTROLS_STATE,
                SEQUENCE,
                new GrammarAction<EndTransactionResponseContainer>( "Process the controls" )
                {
                    public void action( EndTransactionResponseContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();
                        
                        container.setGathering( false );

                        try
                        {
                            List<Control> controls = EndTransactionResponseContainer.decode( value.getData() );
                            
                            // Add the updateControls to the list of updateControls
                            UpdateControls currentUpdateControls = container.getEndTransactionResponse().getCurrentUpdateControls();
                            
                            // Add the decoder controls
                            currentUpdateControls.setControls( controls );
                            
                            // And add the decoded updateControls to the list of updateControls
                            container.getEndTransactionResponse().getUpdateControls().add( currentUpdateControls );
                        }
                        catch ( DecoderException de )
                        {
                            // Add an error
                            LOG.error( I18n
                                .err( I18n.ERR_04099_INVALID_CONTROL_LIST, Strings.dumpBytes( value.getData() ), 
                                    de.getMessage() ) );

                            // This will generate a PROTOCOL_ERROR
                            throw new DecoderException( de.getMessage(), de );
                        }

                        // We may have nothing left
                        container.setGrammarEndAllowed( true );
                    }
                } );

        
        /**
         * Transition from controls to updateControl
         *
         * txnEndReq ::= SEQUENCE {
         *                  ...
         *                  messageID MessageID,
         *     
         * Loop on the updateControl
         */
        super.transitions[EndTransactionResponseStates.CONTROLS_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition<EndTransactionResponseContainer>(
                EndTransactionResponseStates.CONTROLS_STATE,
                EndTransactionResponseStates.UPDATE_CONTROL_SEQ_STATE,
                SEQUENCE,
                new GrammarAction<EndTransactionResponseContainer>( "Get the updateControl messageId" )
                {
                    public void action( EndTransactionResponseContainer container )
                    {
                        // Create a new current UpdateControl
                        UpdateControls currentUpdateControls = new UpdateControls();
                        
                        container.getEndTransactionResponse().setCurrentControls( currentUpdateControls );
                    }
                } );
    }


    /**
     * This class is a singleton.
     * 
     * @return An instance on this grammar
     */
    public static Grammar<EndTransactionResponseContainer> getInstance()
    {
        return instance;
    }
}
