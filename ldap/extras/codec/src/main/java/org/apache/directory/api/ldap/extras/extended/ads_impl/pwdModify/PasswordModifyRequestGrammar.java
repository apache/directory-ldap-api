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
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequestImpl;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements the PasswordModify extended operation's ASN.1 grammer. 
 * All the actions are declared in this class. As it is a singleton, 
 * these declaration are only done once. The grammar is :
 * 
 * <pre>
 *  PasswdModifyRequestValue ::= SEQUENCE {
 *    userIdentity    [0]  OCTET STRING OPTIONAL
 *    oldPasswd       [1]  OCTET STRING OPTIONAL
 *    newPasswd       [2]  OCTET STRING OPTIONAL }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */

public class PasswordModifyRequestGrammar extends AbstractGrammar<PasswordModifyRequestContainer>
{

    /** logger */
    private static final Logger LOG = LoggerFactory.getLogger( PasswordModifyRequestGrammar.class );

    /** Speedup for logs */
    static final boolean IS_DEBUG = LOG.isDebugEnabled();

    /** The instance of grammar. PasswdModifyRequestGrammar is a singleton */
    private static Grammar<PasswordModifyRequestContainer> instance = new PasswordModifyRequestGrammar();


    /**
     * Creates a new PasswordModifyRequestGrammar object.
     */
    @SuppressWarnings("unchecked")
    public PasswordModifyRequestGrammar()
    {
        setName( PasswordModifyRequestGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[PasswordModifyRequestStatesEnum.LAST_PASSWORD_MODIFY_REQUEST_STATE
            .ordinal()][256];

        /**
         * Transition from init state to PasswordModify Request Value
         * 
         * PasswdModifyRequestValue ::= SEQUENCE {
         *     ...
         *     
         * Creates the PasswdModifyRequest object
         */
        super.transitions[PasswordModifyRequestStatesEnum.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] =
            new GrammarTransition<PasswordModifyRequestContainer>(
                PasswordModifyRequestStatesEnum.START_STATE,
                PasswordModifyRequestStatesEnum.PASSWORD_MODIFY_REQUEST_SEQUENCE_STATE,
                UniversalTag.SEQUENCE.getValue(), new GrammarAction<PasswordModifyRequestContainer>(
                    "Init PasswordModifyRequest" )
                {
                    public void action( PasswordModifyRequestContainer container )
                    {
                        PasswordModifyRequestDecorator passwordModifyRequestDecorator = new PasswordModifyRequestDecorator(
                            LdapApiServiceFactory.getSingleton(), new PasswordModifyRequestImpl() );
                        container.setPasswordModifyRequest( passwordModifyRequestDecorator );

                        // We may have nothing left
                        container.setGrammarEndAllowed( true );
                    }
                } );

        /**
         * Transition from PasswordModify Request Value to userIdentity
         *
         * PasswdModifyRequestValue ::= SEQUENCE {
         *     userIdentity    [0]  OCTET STRING OPTIONAL
         *     ...
         *     
         * Set the userIdentity into the PasswdModifyRequest instance.
         */
        super.transitions[PasswordModifyRequestStatesEnum.PASSWORD_MODIFY_REQUEST_SEQUENCE_STATE.ordinal()][PasswordModifyRequestConstants.USER_IDENTITY_TAG] =
            new GrammarTransition<PasswordModifyRequestContainer>(
                PasswordModifyRequestStatesEnum.PASSWORD_MODIFY_REQUEST_SEQUENCE_STATE,
                PasswordModifyRequestStatesEnum.USER_IDENTITY_STATE,
                PasswordModifyRequestConstants.USER_IDENTITY_TAG,
                new GrammarAction<PasswordModifyRequestContainer>( "Set PasswordModifyRequest user identity" )
                {
                    public void action( PasswordModifyRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        byte[] userIdentity = value.getData();

                        if ( IS_DEBUG )
                        {
                            LOG.debug( "UserIdentity = " + Strings.dumpBytes( userIdentity ) );
                        }

                        if ( userIdentity == null )
                        {
                            userIdentity = Strings.EMPTY_BYTES;
                        }

                        container.getPwdModifyRequest().setUserIdentity( userIdentity );

                        // We may have nothing left
                        container.setGrammarEndAllowed( true );
                    }
                } );

        /**
         * Transition from userIdentity to oldPassword
         *
         * PasswdModifyRequestValue ::= SEQUENCE {
         *     userIdentity    [0]  OCTET STRING OPTIONAL
         *     oldPassword     [1]  OCTET STRING OPTIONAL
         *     ...
         *     
         * Set the oldPassword into the PasswdModifyRequest instance.
         */
        super.transitions[PasswordModifyRequestStatesEnum.USER_IDENTITY_STATE.ordinal()][PasswordModifyRequestConstants.OLD_PASSWORD_TAG] =
            new GrammarTransition<PasswordModifyRequestContainer>(
                PasswordModifyRequestStatesEnum.USER_IDENTITY_STATE,
                PasswordModifyRequestStatesEnum.OLD_PASSWORD_STATE,
                PasswordModifyRequestConstants.OLD_PASSWORD_TAG,
                new GrammarAction<PasswordModifyRequestContainer>( "Set PasswordModifyRequest oldPassword" )
                {
                    public void action( PasswordModifyRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        byte[] oldPassword = value.getData();

                        if ( IS_DEBUG )
                        {
                            LOG.debug( "oldPassword = " + Strings.dumpBytes( oldPassword ) );
                        }

                        if ( oldPassword == null )
                        {
                            oldPassword = Strings.EMPTY_BYTES;
                        }

                        container.getPwdModifyRequest().setOldPassword( oldPassword );

                        // We may have nothing left
                        container.setGrammarEndAllowed( true );
                    }
                } );

        /**
         * Transition from userIdentity to newPassword
         *
         * PasswdModifyRequestValue ::= SEQUENCE {
         *     userIdentity    [0]  OCTET STRING OPTIONAL
         *     ...
         *     newPassword     [2]  OCTET STRING OPTIONAL
         * 
         *     
         * Set the newPassword into the PasswdModifyRequest instance.
         */
        super.transitions[PasswordModifyRequestStatesEnum.USER_IDENTITY_STATE.ordinal()][PasswordModifyRequestConstants.NEW_PASSWORD_TAG] =
            new GrammarTransition<PasswordModifyRequestContainer>(
                PasswordModifyRequestStatesEnum.USER_IDENTITY_STATE,
                PasswordModifyRequestStatesEnum.NEW_PASSWORD_STATE,
                PasswordModifyRequestConstants.NEW_PASSWORD_TAG,
                new GrammarAction<PasswordModifyRequestContainer>( "Set PasswordModifyRequest newPassword" )
                {
                    public void action( PasswordModifyRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        byte[] newPassword = value.getData();

                        if ( IS_DEBUG )
                        {
                            LOG.debug( "newPassword = " + Strings.dumpBytes( newPassword ) );
                        }

                        if ( newPassword == null )
                        {
                            newPassword = Strings.EMPTY_BYTES;
                        }

                        container.getPwdModifyRequest().setNewPassword( newPassword );

                        // We may have nothing left
                        container.setGrammarEndAllowed( true );
                    }
                } );

        /**
         * Transition from PasswordModify Request Value to oldPassword
         *
         * PasswdModifyRequestValue ::= SEQUENCE {
         *     ...
         *     oldPassword    [1]  OCTET STRING OPTIONAL
         *     ...
         *     
         * Set the oldPassword into the PasswdModifyRequest instance.
         */
        super.transitions[PasswordModifyRequestStatesEnum.PASSWORD_MODIFY_REQUEST_SEQUENCE_STATE.ordinal()][PasswordModifyRequestConstants.OLD_PASSWORD_TAG] =
            new GrammarTransition<PasswordModifyRequestContainer>(
                PasswordModifyRequestStatesEnum.PASSWORD_MODIFY_REQUEST_SEQUENCE_STATE,
                PasswordModifyRequestStatesEnum.OLD_PASSWORD_STATE,
                PasswordModifyRequestConstants.OLD_PASSWORD_TAG,
                new GrammarAction<PasswordModifyRequestContainer>( "Set PasswordModifyRequest oldPassword" )
                {
                    public void action( PasswordModifyRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        byte[] oldPassword = value.getData();

                        if ( IS_DEBUG )
                        {
                            LOG.debug( "OldPassword = " + Strings.dumpBytes( oldPassword ) );
                        }

                        if ( oldPassword == null )
                        {
                            oldPassword = Strings.EMPTY_BYTES;
                        }

                        container.getPwdModifyRequest().setOldPassword( oldPassword );

                        // We may have nothing left
                        container.setGrammarEndAllowed( true );
                    }
                } );

        /**
         * Transition from PasswordModify Request Value to newPassword
         *
         * PasswdModifyRequestValue ::= SEQUENCE {
         *     ...
         *     newPassword    [2]  OCTET STRING OPTIONAL
         * }
         *     
         * Set the newPassword into the PasswdModifyRequest instance.
         */
        super.transitions[PasswordModifyRequestStatesEnum.PASSWORD_MODIFY_REQUEST_SEQUENCE_STATE.ordinal()][PasswordModifyRequestConstants.NEW_PASSWORD_TAG] =
            new GrammarTransition<PasswordModifyRequestContainer>(
                PasswordModifyRequestStatesEnum.PASSWORD_MODIFY_REQUEST_SEQUENCE_STATE,
                PasswordModifyRequestStatesEnum.NEW_PASSWORD_STATE,
                PasswordModifyRequestConstants.NEW_PASSWORD_TAG,
                new GrammarAction<PasswordModifyRequestContainer>( "Set PasswordModifyRequest newPassword" )
                {
                    public void action( PasswordModifyRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        byte[] newPassword = value.getData();

                        if ( IS_DEBUG )
                        {
                            LOG.debug( "NewPassword = " + Strings.dumpBytes( newPassword ) );
                        }

                        if ( newPassword == null )
                        {
                            newPassword = Strings.EMPTY_BYTES;
                        }

                        container.getPwdModifyRequest().setNewPassword( newPassword );

                        // We may have nothing left
                        container.setGrammarEndAllowed( true );
                    }
                } );

        /**
         * Transition from oldPassword to newPassword
         *
         *     ...
         *     oldPassword    [1]  OCTET STRING OPTIONAL
         *     newPassword    [2]  OCTET STRING OPTIONAL
         * }
         *     
         * Set the newPassword into the PasswdModifyRequest instance.
         */
        super.transitions[PasswordModifyRequestStatesEnum.OLD_PASSWORD_STATE.ordinal()][PasswordModifyRequestConstants.NEW_PASSWORD_TAG] =
            new GrammarTransition<PasswordModifyRequestContainer>(
                PasswordModifyRequestStatesEnum.OLD_PASSWORD_STATE,
                PasswordModifyRequestStatesEnum.NEW_PASSWORD_STATE,
                PasswordModifyRequestConstants.NEW_PASSWORD_TAG,
                new GrammarAction<PasswordModifyRequestContainer>( "Set PasswordModifyRequest newPassword" )
                {
                    public void action( PasswordModifyRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        byte[] newPassword = value.getData();

                        if ( IS_DEBUG )
                        {
                            LOG.debug( "NewPassword = " + Strings.dumpBytes( newPassword ) );
                        }

                        if ( newPassword == null )
                        {
                            newPassword = Strings.EMPTY_BYTES;
                        }

                        container.getPwdModifyRequest().setNewPassword( newPassword );

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
    public static Grammar<PasswordModifyRequestContainer> getInstance()
    {
        return instance;
    }
}
