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
package org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction.controls;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction.controls.actions.AddControl;
import org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction.controls.actions.StoreControlCriticality;
import org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction.controls.actions.StoreControlValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.directory.api.asn1.ber.tlv.UniversalTag.BOOLEAN;
import static org.apache.directory.api.asn1.ber.tlv.UniversalTag.OCTET_STRING;
import static org.apache.directory.api.asn1.ber.tlv.UniversalTag.SEQUENCE;

/**
 * A grammar to decode controls in a EndTransactionResponse extended operation
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ControlsGrammar extends AbstractGrammar<ControlsContainer>
{
    /** logger */
    private static final Logger LOG = LoggerFactory.getLogger( ControlsGrammar.class );

    /** Speedup for logs */
    static final boolean IS_DEBUG = LOG.isDebugEnabled();

    /** The instance of grammar. ControlsGrammar is a singleton */
    private static Grammar<ControlsContainer> instance = new ControlsGrammar();


    /**
     * Creates a new ControlsGrammar object.
     */
    @SuppressWarnings("unchecked")
    public ControlsGrammar()
    {
        setName( ControlsGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[ControlsStates.LAST_STATE.ordinal()][256];

        /**
         * Transition from init state to Control Sequence
         * 
         *  Control ::= SEQUENCE {
         *     ...
         *     
         * Creates the current control instance
         */
        super.transitions[ControlsStates.START_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition<ControlsContainer>(
                ControlsStates.START_STATE,
                ControlsStates.CONTROL_SEQUENCE_STATE,
                SEQUENCE, 
                new GrammarAction<ControlsContainer>( "Init Control" )
                {
                    public void action( ControlsContainer container ) throws DecoderException
                    {
                        TLV tlv = container.getCurrentTLV();
                        int expectedLength = tlv.getLength();

                        // The Length should be null
                        if ( expectedLength == 0 )
                        {
                            String msg = I18n.err( I18n.ERR_04096_NULL_CONTROL_LENGTH );
                            LOG.error( msg );

                            // This will generate a PROTOCOL_ERROR
                            throw new DecoderException( msg );
                        }
                    }
                } );

        /**
         * Transition from controlSequence state to control type
         * 
         *  Control ::= SEQUENCE {
         *     controlType             LDAPOID,
         *     ...
         *     
         * Creates the current control instance
         */
        super.transitions[ControlsStates.CONTROL_SEQUENCE_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition<ControlsContainer>(
                ControlsStates.CONTROL_SEQUENCE_STATE,
                ControlsStates.CONTROL_TYPE_STATE,
                OCTET_STRING, 
                new AddControl() );

        /**
         * Transition from control type to control criticality
         * 
         *  Control ::= SEQUENCE {
         *     controlType             LDAPOID,
         *     criticality             BOOLEAN DEFAULT FALSE,
         *     ...
         *     
         * Store the criticality
         */
        super.transitions[ControlsStates.CONTROL_TYPE_STATE.ordinal()][BOOLEAN.getValue()] =
            new GrammarTransition<ControlsContainer>(
                ControlsStates.CONTROL_TYPE_STATE,
                ControlsStates.CONTROL_CRITICALITY_STATE,
                BOOLEAN, 
                new StoreControlCriticality() );

        /**
         * Transition from control type to control value
         * 
         *  Control ::= SEQUENCE {
         *     controlType             LDAPOID,
         *     ...
         *     controlValue            OCTET STRING OPTIONAL }
         *     
         * Store the value
         */
        super.transitions[ControlsStates.CONTROL_TYPE_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition<ControlsContainer>(
                ControlsStates.CONTROL_TYPE_STATE,
                ControlsStates.CONTROL_VALUE_STATE,
                OCTET_STRING, 
                new StoreControlValue() );

        /**
         * Transition from control type to control sequence
         * 
         *  Control ::= SEQUENCE {
         *     controlType             LDAPOID,
         *     
         * Nothing to do
         */
        super.transitions[ControlsStates.CONTROL_TYPE_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition<ControlsContainer>(
                ControlsStates.CONTROL_TYPE_STATE,
                ControlsStates.CONTROL_SEQUENCE_STATE,
                SEQUENCE );
        
        /**
         * Transition from control criticality to control value
         * 
         *  Control ::= SEQUENCE {
         *     ...
         *     criticality             BOOLEAN DEFAULT FALSE,
         *     controlValue            OCTET STRING OPTIONAL }
         *     
         * Store the value
         */
        super.transitions[ControlsStates.CONTROL_CRITICALITY_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition<ControlsContainer>(
                ControlsStates.CONTROL_CRITICALITY_STATE,
                ControlsStates.CONTROL_VALUE_STATE,
                OCTET_STRING, 
                new StoreControlValue() );
        
        /**
         * Transition from control criticality to control sequence
         * 
         *  Control ::= SEQUENCE {
         *     ...
         *     criticality             BOOLEAN DEFAULT FALSE,
         *     
         * Nothing to do
         */
        super.transitions[ControlsStates.CONTROL_CRITICALITY_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition<ControlsContainer>(
                ControlsStates.CONTROL_CRITICALITY_STATE,
                ControlsStates.CONTROL_SEQUENCE_STATE,
                SEQUENCE );

        /**
         * Transition from control value to control sequence
         * 
         *  Control ::= SEQUENCE {
         *     
         * Nothing to do
         */
        super.transitions[ControlsStates.CONTROL_VALUE_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition<ControlsContainer>(
                ControlsStates.CONTROL_VALUE_STATE,
                ControlsStates.CONTROL_SEQUENCE_STATE,
                SEQUENCE ); 
    }


    /**
     * This class is a singleton.
     * 
     * @return An instance on this grammar
     */
    public static Grammar<ControlsContainer> getInstance()
    {
        return instance;
    }
}
