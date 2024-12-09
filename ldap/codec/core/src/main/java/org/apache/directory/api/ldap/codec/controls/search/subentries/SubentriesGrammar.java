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
package org.apache.directory.api.ldap.codec.controls.search.subentries;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.BooleanDecoder;
import org.apache.directory.api.asn1.ber.tlv.BooleanDecoderException;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements the SubEntryControl. All the actions are declared in
 * this class. As it is a singleton, these declaration are only done once.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class SubentriesGrammar extends AbstractGrammar<SubentriesContainer>
{
    /** The logger */
    static final Logger LOG = LoggerFactory.getLogger( SubentriesGrammar.class );

    /** The instance of grammar. SubEntryControlGrammar is a singleton */
    private static Grammar<SubentriesContainer> instance = new SubentriesGrammar();


    /**
     * Creates a new SubEntryGrammar object.
     */
    @SuppressWarnings("unchecked")
    private SubentriesGrammar()
    {
        setName( SubentriesGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[SubentriesStates.LAST_SUB_ENTRY_STATE.ordinal()][256];

        super.transitions[SubentriesStates.START_STATE.ordinal()][UniversalTag.BOOLEAN.getValue()] =
            new GrammarTransition<SubentriesContainer>( SubentriesStates.START_STATE,
                SubentriesStates.SUB_ENTRY_VISIBILITY_STATE, UniversalTag.BOOLEAN.getValue(),
                new GrammarAction<SubentriesContainer>( "SubEntryControl visibility" )
                {
                    public void action( SubentriesContainer container ) throws DecoderException
                    {
                        TLV tlv = container.getCurrentTLV();

                        // We get the value. If it's a 0, it's a FALSE. If it's
                        // a FF, it's a TRUE. Any other value should be an error,
                        // but we could relax this constraint. So if we have
                        // something
                        // which is not 0, it will be interpreted as TRUE, but we
                        // will generate a warning.
                        BerValue value = tlv.getValue();

                        try
                        {
                            container.getSubentriesControl().setVisibility( BooleanDecoder.parse( value ) );

                            // We can have an END transition
                            container.setGrammarEndAllowed( true );
                        }
                        catch ( BooleanDecoderException bde )
                        {
                            LOG.error( I18n.err( I18n.ERR_05310_INVALID_VISIBILITY_FLAG, Strings.dumpBytes( value.getData() ), bde.getMessage() ) );

                            // This will generate a PROTOCOL_ERROR
                            throw new DecoderException( bde.getMessage() );
                        }
                    }
                }, FollowUp.OPTIONAL );
    }


    /**
     * This class is a singleton.
     * 
     * @return An instance on this grammar
     */
    public static Grammar<SubentriesContainer> getInstance()
    {
        return instance;
    }
}
