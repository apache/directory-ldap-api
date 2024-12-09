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
package org.apache.directory.api.ldap.extras.extended.ads_impl.certGeneration;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements the Certificate generation extended operation's ASN.1 grammer. 
 * All the actions are declared in this class. As it is a singleton, 
 * these declaration are only done once. The grammar is :
 * 
 * <pre>
 *   CertGenerateObject ::= SEQUENCE 
 *   {
 *      targetDN        IA5String,
 *      issuerDN        IA5String,
 *      subjectDN       IA5String,
 *      keyAlgorithm    IA5String
 *   }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */

public class CertGenerationRequestGrammar extends AbstractGrammar<CertGenerationRequestContainer>
{

    /** logger */
    private static final Logger LOG = LoggerFactory.getLogger( CertGenerationRequestGrammar.class );

    /** The instance of grammar. CertGenerationObjectGrammar is a singleton */
    private static Grammar<CertGenerationRequestContainer> instance = new CertGenerationRequestGrammar();


    /**
     * Creates a new CertGenerationGrammar object.
     */
    @SuppressWarnings("unchecked")
    public CertGenerationRequestGrammar()
    {
        setName( CertGenerationRequestGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[CertGenerationRequestStatesEnum.LAST_CERT_GENERATION_STATE.ordinal()][256];

        /**
         * Transition from init state to certificate generation
         * 
         * CertGenerationObject ::= SEQUENCE {
         *     ...
         *     
         * Creates the CertGenerationObject object
         */
        super.transitions[CertGenerationRequestStatesEnum.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] =
            new GrammarTransition<CertGenerationRequestContainer>(
                CertGenerationRequestStatesEnum.START_STATE, 
                CertGenerationRequestStatesEnum.CERT_GENERATION_REQUEST_SEQUENCE_STATE,
                UniversalTag.SEQUENCE.getValue(),
                null,
                FollowUp.MANDATORY );

        /**
         * Transition from certificate generation request to targetDN
         *
         * CertGenerationObject ::= SEQUENCE { 
         *     targetDN IA5String,
         *     ...
         *     
         * Set the targetDN value into the CertGenerationObject instance.
         */
        super.transitions[CertGenerationRequestStatesEnum.CERT_GENERATION_REQUEST_SEQUENCE_STATE.ordinal()][UniversalTag.OCTET_STRING
            .getValue()] =
            new GrammarTransition<CertGenerationRequestContainer>(
                CertGenerationRequestStatesEnum.CERT_GENERATION_REQUEST_SEQUENCE_STATE,
                CertGenerationRequestStatesEnum.TARGETDN_STATE, UniversalTag.OCTET_STRING.getValue(),
                new GrammarAction<CertGenerationRequestContainer>( "Set Cert Generation target Dn value" )
                {
                    public void action( CertGenerationRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        String targetDN = Strings.utf8ToString( value.getData() );

                        if ( LOG.isDebugEnabled() )
                        {
                            LOG.debug( I18n.msg( I18n.MSG_08215_TARGET_DN, targetDN ) );
                        }

                        if ( ( targetDN != null ) && ( targetDN.trim().length() > 0 ) )
                        {
                            if ( !Dn.isValid( targetDN ) )
                            {
                                String msg = I18n.err( I18n.ERR_08201_INVALID_TARGET_DN, targetDN );
                                LOG.error( msg );
                                throw new DecoderException( msg );
                            }

                            container.getCertGenerationRequest().setTargetDN( targetDN );
                        }
                        else
                        {
                            String msg = I18n.err( I18n.ERR_08202_NULL_TARGET_DN_DECODING_FAILED, Strings.dumpBytes( value.getData() ) );
                            LOG.error( msg );
                            throw new DecoderException( msg );
                        }
                    }
                },
                FollowUp.MANDATORY );

        /**
         * Transition from targetDN state to issuerDN
         *
         * CertGenerationObject ::= SEQUENCE { 
         *     ...
         *     issuerDN IA5String,
         *     ...
         *     
         * Set the issuerDN value into the CertGenerationObject instance.
         */
        super.transitions[CertGenerationRequestStatesEnum.TARGETDN_STATE.ordinal()][UniversalTag.OCTET_STRING.getValue()] =
            new GrammarTransition<CertGenerationRequestContainer>( 
                CertGenerationRequestStatesEnum.TARGETDN_STATE,
                CertGenerationRequestStatesEnum.ISSUER_STATE, UniversalTag.OCTET_STRING.getValue(),
                new GrammarAction<CertGenerationRequestContainer>( "Set Cert Generation issuer Dn value" )
                {
                    public void action( CertGenerationRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        String issuerDN = Strings.utf8ToString( value.getData() );

                        if ( LOG.isDebugEnabled() )
                        {
                            LOG.debug( I18n.msg( I18n.MSG_08207_ISSUER_DN, issuerDN ) );
                        }

                        if ( ( issuerDN != null ) && ( issuerDN.trim().length() > 0 ) )
                        {
                            if ( !Dn.isValid( issuerDN ) )
                            {
                                String msg = I18n.err( I18n.ERR_08203_INVALID_ISSUER_DN, issuerDN );
                                LOG.error( msg );
                                throw new DecoderException( msg );
                            }

                            container.getCertGenerationRequest().setIssuerDN( issuerDN );
                        }
                    }
                },
                FollowUp.MANDATORY );

        /**
         * Transition from issuerDN state to subjectDN
         *
         * CertGenerationObject ::= SEQUENCE {
         *     ... 
         *     subjectDN IA5String,
         *     ...
         *     
         * Set the subjectDN value into the CertGenerationObject instance.
         */
        super.transitions[CertGenerationRequestStatesEnum.ISSUER_STATE.ordinal()][UniversalTag.OCTET_STRING.getValue()] =
            new GrammarTransition<CertGenerationRequestContainer>( 
                CertGenerationRequestStatesEnum.ISSUER_STATE,
                CertGenerationRequestStatesEnum.SUBJECT_STATE, UniversalTag.OCTET_STRING.getValue(),
                new GrammarAction<CertGenerationRequestContainer>( "Set Cert Generation subject Dn value" )
                {
                    public void action( CertGenerationRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        String subjectDN = Strings.utf8ToString( value.getData() );

                        if ( LOG.isDebugEnabled() )
                        {
                            LOG.debug( I18n.msg( I18n.MSG_08219_SUBJECT_DN, subjectDN ) );
                        }

                        if ( ( subjectDN != null ) && ( subjectDN.trim().length() > 0 ) )
                        {
                            if ( !Dn.isValid( subjectDN ) )
                            {
                                String msg = I18n.err( I18n.ERR_08204_INVALID_SUBJECT_DN, subjectDN );
                                LOG.error( msg );
                                throw new DecoderException( msg );
                            }

                            container.getCertGenerationRequest().setSubjectDN( subjectDN );
                        }
                        else
                        {
                            String msg = I18n.err( I18n.ERR_08202_NULL_TARGET_DN_DECODING_FAILED, Strings.dumpBytes( value.getData() ) );
                            LOG.error( msg );
                            throw new DecoderException( msg );
                        }
                    }
                },
                FollowUp.MANDATORY );

        /**
         * Transition from subjectDN state to keyAlgo
         *
         * CertGenerationObject ::= SEQUENCE { 
         *     ...
         *     keyAlgorithm IA5String
         *     
         * Set the key algorithm value into the CertGenerationObject instance.
         */
        super.transitions[CertGenerationRequestStatesEnum.SUBJECT_STATE.ordinal()][UniversalTag.OCTET_STRING.getValue()] =
            new GrammarTransition<CertGenerationRequestContainer>( 
                CertGenerationRequestStatesEnum.SUBJECT_STATE,
                CertGenerationRequestStatesEnum.KEY_ALGORITHM_STATE,
                UniversalTag.OCTET_STRING.getValue(),
                new GrammarAction<CertGenerationRequestContainer>( "Set Cert Generation key algorithm value" )
                {
                    public void action( CertGenerationRequestContainer container )
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        String keyAlgorithm = Strings.utf8ToString( value.getData() );

                        if ( LOG.isDebugEnabled() )
                        {
                            LOG.debug( I18n.msg( I18n.MSG_08218_KEY_ALGORITHM, keyAlgorithm ) );
                        }

                        if ( keyAlgorithm != null && ( keyAlgorithm.trim().length() > 0 ) )
                        {
                            container.getCertGenerationRequest().setKeyAlgorithm( keyAlgorithm );
                        }

                        container.setGrammarEndAllowed( true );
                    }
                },
                FollowUp.OPTIONAL );

    }


    /**
     * This class is a singleton.
     * 
     * @return An instance on this grammar
     */
    public static Grammar<CertGenerationRequestContainer> getInstance()
    {
        return instance;
    }
}
