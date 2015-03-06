/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.api.ldap.extras.controls.vlv_impl;


import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * TODO VirtualListViewRequestGrammar.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class VirtualListViewRequestGrammar extends AbstractGrammar<VirtualListViewRequestContainer>
{
    static final Logger LOG = LoggerFactory.getLogger( VirtualListViewRequestGrammar.class );

    static final boolean IS_DEBUG = LOG.isDebugEnabled();

    private static Grammar<?> instance = new VirtualListViewRequestGrammar();


    @SuppressWarnings("unchecked")
    private VirtualListViewRequestGrammar()
    {
        setName( VirtualListViewRequestGrammar.class.getName() );

        super.transitions = new GrammarTransition[VirtualListViewRequestStates.END_STATE.ordinal()][256];

        super.transitions[VirtualListViewRequestStates.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>(
                VirtualListViewRequestStates.START_STATE,
                VirtualListViewRequestStates.VLV_SEQUENCE_STATE,
                UniversalTag.SEQUENCE.getValue(),
                null );

        super.transitions[VirtualListViewRequestStates.VLV_SEQUENCE_STATE.ordinal()][UniversalTag.INTEGER.getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>(
                VirtualListViewRequestStates.VLV_SEQUENCE_STATE,
                VirtualListViewRequestStates.VLV_BEFORE_COUNT_STATE,
                UniversalTag.INTEGER.getValue(),
                new StoreBeforeCount() );

        super.transitions[VirtualListViewRequestStates.VLV_BEFORE_COUNT_STATE.ordinal()][UniversalTag.INTEGER
            .getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>(
                VirtualListViewRequestStates.VLV_BEFORE_COUNT_STATE,
                VirtualListViewRequestStates.VLV_AFTER_COUNT_STATE,
                UniversalTag.INTEGER.getValue(),
                new StoreAfterCount() );

        super.transitions[VirtualListViewRequestStates.VLV_AFTER_COUNT_STATE.ordinal()][VirtualListViewerTags.BY_OFFSET_TAG
            .getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>(
                VirtualListViewRequestStates.VLV_AFTER_COUNT_STATE,
                VirtualListViewRequestStates.VLV_TARGET_BY_OFFSET_STATE,
                ( byte ) VirtualListViewerTags.BY_OFFSET_TAG.getValue(),
                null );

        super.transitions[VirtualListViewRequestStates.VLV_AFTER_COUNT_STATE.ordinal()][VirtualListViewerTags.ASSERTION_VALUE_TAG
            .getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>(
                VirtualListViewRequestStates.VLV_AFTER_COUNT_STATE,
                VirtualListViewRequestStates.VLV_ASSERTION_VALUE_STATE,
                ( byte ) VirtualListViewerTags.ASSERTION_VALUE_TAG.getValue(),
                new StoreAssertionValue() );

        super.transitions[VirtualListViewRequestStates.VLV_TARGET_BY_OFFSET_STATE.ordinal()][UniversalTag.INTEGER
            .getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>(
                VirtualListViewRequestStates.VLV_TARGET_BY_OFFSET_STATE,
                VirtualListViewRequestStates.VLV_OFFSET_STATE,
                UniversalTag.INTEGER.getValue(),
                new StoreOffset() );

        super.transitions[VirtualListViewRequestStates.VLV_OFFSET_STATE.ordinal()][UniversalTag.INTEGER.getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>(
                VirtualListViewRequestStates.VLV_OFFSET_STATE,
                VirtualListViewRequestStates.VLV_CONTENT_COUNT_STATE,
                UniversalTag.INTEGER.getValue(),
                new StoreContentCount() );

        super.transitions[VirtualListViewRequestStates.VLV_CONTENT_COUNT_STATE.ordinal()][UniversalTag.OCTET_STRING
            .getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>(
                VirtualListViewRequestStates.VLV_CONTENT_COUNT_STATE,
                VirtualListViewRequestStates.VLV_CONTEXT_ID_STATE,
                UniversalTag.OCTET_STRING.getValue(),
                new StoreContextId() );

        super.transitions[VirtualListViewRequestStates.VLV_ASSERTION_VALUE_STATE.ordinal()][UniversalTag.OCTET_STRING
            .getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>(
                VirtualListViewRequestStates.VLV_ASSERTION_VALUE_STATE,
                VirtualListViewRequestStates.VLV_CONTEXT_ID_STATE,
                UniversalTag.OCTET_STRING.getValue(),
                new StoreContextId() );
    }


    public static Grammar<?> getInstance()
    {
        return instance;
    }
}
