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
 * The grammar for the VLV response which described as :
 * 
 * <pre>
 *  VirtualListViewResponse ::= SEQUENCE {
 *         targetPosition    INTEGER (0 .. maxInt),
 *         contentCount     INTEGER (0 .. maxInt),
 *         virtualListViewResult ENUMERATED {
 *              success (0),
 *              operationsError (1),
 *              protocolError (3),
 *              unwillingToPerform (53),
 *              insufficientAccessRights (50),
 *              timeLimitExceeded (3),
 *              adminLimitExceeded (11),
 *              innapropriateMatching (18),
 *              sortControlMissing (60),
 *              offsetRangeError (61),
 *              other(80),
 *              ... 
 *         },
 *         contextID     OCTET STRING OPTIONAL 
 * }
 * </pre>
 * 
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class VirtualListViewResponseGrammar extends AbstractGrammar<VirtualListViewResponseContainer>
{
    static final Logger LOG = LoggerFactory.getLogger( VirtualListViewResponseGrammar.class );

    static final boolean IS_DEBUG = LOG.isDebugEnabled();

    private static Grammar<?> instance = new VirtualListViewResponseGrammar();


    /**
     * Creates a new VirtualListViewResponseGrammar object.
     */
    @SuppressWarnings("unchecked")
    private VirtualListViewResponseGrammar()
    {
        setName( VirtualListViewResponseGrammar.class.getName() );

        super.transitions = new GrammarTransition[VirtualListViewResponseStates.END_STATE.ordinal()][256];

        super.transitions[VirtualListViewResponseStates.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] =
            new GrammarTransition<VirtualListViewResponseContainer>(
                VirtualListViewResponseStates.START_STATE,
                VirtualListViewResponseStates.VLV_SEQUENCE_STATE,
                UniversalTag.SEQUENCE.getValue(),
                null );

        super.transitions[VirtualListViewResponseStates.VLV_SEQUENCE_STATE.ordinal()][UniversalTag.INTEGER.getValue()] =
            new GrammarTransition<VirtualListViewResponseContainer>(
                VirtualListViewResponseStates.VLV_SEQUENCE_STATE,
                VirtualListViewResponseStates.VLV_TARGET_POSITION_STATE,
                UniversalTag.INTEGER.getValue(),
                new StoreTargetPosition() );

        super.transitions[VirtualListViewResponseStates.VLV_TARGET_POSITION_STATE.ordinal()][UniversalTag.INTEGER
            .getValue()] =
            new GrammarTransition<VirtualListViewResponseContainer>(
                VirtualListViewResponseStates.VLV_TARGET_POSITION_STATE,
                VirtualListViewResponseStates.VLV_CONTENT_COUNT_STATE,
                UniversalTag.INTEGER.getValue(),
                new StoreContentCountResponse() );

        super.transitions[VirtualListViewResponseStates.VLV_CONTENT_COUNT_STATE.ordinal()][UniversalTag.ENUMERATED
            .getValue()] =
            new GrammarTransition<VirtualListViewResponseContainer>(
                VirtualListViewResponseStates.VLV_CONTENT_COUNT_STATE,
                VirtualListViewResponseStates.VLV_VIRTUAL_LIST_VIEW_RESULT_STATE,
                UniversalTag.ENUMERATED.getValue(),
                new StoreVirtualListViewResult() );

        super.transitions[VirtualListViewResponseStates.VLV_VIRTUAL_LIST_VIEW_RESULT_STATE.ordinal()][UniversalTag.OCTET_STRING
            .getValue()] =
            new GrammarTransition<VirtualListViewResponseContainer>(
                VirtualListViewResponseStates.VLV_VIRTUAL_LIST_VIEW_RESULT_STATE,
                VirtualListViewResponseStates.VLV_CONTEXT_ID_STATE,
                UniversalTag.OCTET_STRING.getValue(),
                new StoreContextIdResponse() );
    }


    /**
     * @return the singleton instance of the VirtualListViewResponseGrammar
     */
    public static Grammar<?> getInstance()
    {
        return instance;
    }
}
