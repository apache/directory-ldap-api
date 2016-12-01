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
package org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyResponseImpl;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements the PasswordModifyResponse extended operation's ASN.1 grammer. 
 * All the actions are declared in this class. As it is a singleton, 
 * these declaration are only done once. The grammar is :
 * 
 * <pre>
 *  PasswdModifyResponseValue ::= SEQUENCE {
 *      genPasswd       [0]     OCTET STRING OPTIONAL }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */

public class PasswordModifyResponseGrammar extends AbstractGrammar<PasswordModifyResponseContainer>
{

    /** logger */
    private static final Logger LOG = LoggerFactory.getLogger( PasswordModifyResponseGrammar.class );

    /** Speedup for logs */
    static final boolean IS_DEBUG = LOG.isDebugEnabled();

    /** The instance of grammar. PasswdModifyResponseGrammar is a singleton */
    private static Grammar<PasswordModifyResponseContainer> instance = new PasswordModifyResponseGrammar();


    /**
     * Creates a new PasswordModifyResponseGrammar object.
     */
    @SuppressWarnings("unchecked")
    public PasswordModifyResponseGrammar()
    {
        setName( PasswordModifyResponseGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[PasswordModifyResponseStatesEnum.LAST_PASSWORD_MODIFY_RESPONSE_STATE
            .ordinal()][256];

        /**
         * Transition from init state to PasswordModify Response Value
         * 
         * PasswdModifyResponseValue ::= SEQUENCE {
         *     ...
         *     
         * Creates the PasswdModifyResponse object
         */
        super.transitions[PasswordModifyResponseStatesEnum.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] =
            new GrammarTransition<PasswordModifyResponseContainer>(
                PasswordModifyResponseStatesEnum.START_STATE,
                PasswordModifyResponseStatesEnum.PASSWORD_MODIFY_RESPONSE_SEQUENCE_STATE,
                UniversalTag.SEQUENCE.getValue(), new GrammarAction<PasswordModifyResponseContainer>(
                    "Init PasswordModifyResponse" )
                {
                    public void action( PasswordModifyResponseContainer container )
                    {
                        PasswordModifyResponseDecorator passwordModifyResponse = new PasswordModifyResponseDecorator(
                            LdapApiServiceFactory.getSingleton(), new PasswordModifyResponseImpl() );
                        container.setPasswordModifyResponse( passwordModifyResponse );

                        // We may have nothing left
                        container.setGrammarEndAllowed( true );
                    }
                } );

        /**
         * Transition from PasswordModify Response Value to genPassword
         *
         * PasswdModifyResponseValue ::= SEQUENCE {
         *     genPassword    [0]  OCTET STRING OPTIONAL
         *     ...
         *     
         * Set the userIdentity into the PasswdModifyResponset instance.
         */
        super.transitions[PasswordModifyResponseStatesEnum.PASSWORD_MODIFY_RESPONSE_SEQUENCE_STATE.ordinal()][PasswordModifyResponseConstants.GEN_PASSWORD_TAG] =
            new GrammarTransition<PasswordModifyResponseContainer>(
                PasswordModifyResponseStatesEnum.PASSWORD_MODIFY_RESPONSE_SEQUENCE_STATE,
                PasswordModifyResponseStatesEnum.GEN_PASSWORD_STATE,
                PasswordModifyResponseConstants.GEN_PASSWORD_TAG,
                new GrammarAction<PasswordModifyResponseContainer>( "Set PasswordModifyResponse user identity" )
                {
                    public void action( PasswordModifyResponseContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        byte[] genPassword = value.getData();

                        if ( IS_DEBUG )
                        {
                            LOG.debug( "GenPassword = " + Strings.dumpBytes( genPassword ) );
                        }

                        if ( genPassword == null )
                        {
                            genPassword = Strings.EMPTY_BYTES;
                        }

                        container.getPwdModifyResponse().setGenPassword( genPassword );

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
    public static Grammar<PasswordModifyResponseContainer> getInstance()
    {
        return instance;
    }
}
