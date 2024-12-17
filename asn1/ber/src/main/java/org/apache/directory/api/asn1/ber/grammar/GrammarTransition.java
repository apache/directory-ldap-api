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
package org.apache.directory.api.asn1.ber.grammar;


import org.apache.directory.api.asn1.ber.Asn1Container;
import org.apache.directory.api.asn1.ber.grammar.Grammar.FollowUp;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.asn1.util.Asn1StringUtils;


/**
 * Define a transition between two states of a grammar. It stores the next
 * state, and the action to execute while executing the transition.
 * 
 * @param <C> The container type
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class GrammarTransition<C extends Asn1Container>
{
    /** The action associated to the transition */
    private Action<C> action;

    /** The previous state */
    private Enum<?> previousState;

    /** The current state */
    private Enum<?> currentState;

    /** The current tag */
    private int currentTag;
    
    /** Tells if the current TLV has a follow up or not for a given PDU */
    private FollowUp followUp;


    /**
     * Creates a new GrammarTransition object.
     *
     * @param previousState the previous state
     * @param currentState The current state
     * @param currentTag the current TLV's tag
     * @param action The action to execute. It could be null.
     * @param followUp if the current TLV has a follow up in the current PDU
     */
    public GrammarTransition( Enum<?> previousState, Enum<?> currentState, int currentTag, Action<C> action, FollowUp followUp )
    {
        this.previousState = previousState;
        this.currentState = currentState;
        this.action = action;
        this.currentTag = currentTag;
        this.followUp = followUp;
    }


    /**
     * Creates a new GrammarTransition object.
     *
     * @param previousState the previous state
     * @param currentState The current state
     * @param currentTag the current TLV's tag
     * @param followUp if the current TLV has a follow up in the current PDU
     */
    public GrammarTransition( Enum<?> previousState, Enum<?> currentState, int currentTag, FollowUp followUp )
    {
        this.previousState = previousState;
        this.currentState = currentState;
        this.currentTag = currentTag;
        this.followUp = followUp;
    }


    /**
     * Creates a new GrammarTransition object.
     *
     * @param previousState the previous state
     * @param currentState The current state
     * @param currentTag the current TLV's tag
     * @param action The action to execute. It could be null.
     * @param followUp if the current TLV has a follow up in the current PDU
     */
    public GrammarTransition( Enum<?> previousState, Enum<?> currentState, UniversalTag currentTag, Action<C> action, FollowUp followUp )
    {
        this.previousState = previousState;
        this.currentState = currentState;
        this.action = action;
        this.currentTag = currentTag.getValue();
        this.followUp = followUp;
    }


    /**
     * Creates a new GrammarTransition object.
     *
     * @param previousState the previous state
     * @param currentState The current state
     * @param currentTag the current TLV's tag
     * @param followUp if the current TLV has a follow up in the current PDU
     */
    public GrammarTransition( Enum<?> previousState, Enum<?> currentState, UniversalTag currentTag, FollowUp followUp )
    {
        this.previousState = previousState;
        this.currentState = currentState;
        this.currentTag = currentTag.getValue();
        this.followUp = followUp;
    }


    /**
     * Tells if the transition has an associated action.
     *
     * @return <code>true</code> if an action has been associated to the transition
     */
    public boolean hasAction()
    {
        return action != null;
    }


    /**
     * @return Returns the action associated with the transition
     */
    public Action<C> getAction()
    {
        return action;
    }


    /**
     * @return The current state
     */
    public Enum<?> getCurrentState()
    {
        return currentState;
    }


    /**
     * @return The previous state
     */
    public Enum<?> getPreviousState()
    {
        return previousState;
    }


    /**
     * @return the followUp flag
     */
    public boolean hasFollowUp()
    {
        return followUp == FollowUp.MANDATORY;
    }


    /**
     * @param followUp the followUp flag to set
     */
    public void setFollowUp( FollowUp followUp )
    {
        this.followUp = followUp;
    }


    /**
     * @return A representation of the transition as a string.
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "Transition from state <" ).append( previousState ).append( "> " );
        sb.append( "to state <" ).append( currentState ).append( ">, " );
        sb.append( "tag <" ).append( Asn1StringUtils.dumpByte( ( byte ) currentTag ) ).append( ">, " );
        sb.append( "action : " );

        if ( action == null )
        {
            sb.append( "no action" );
        }
        else
        {
            sb.append( action );
        }
        
        if ( FollowUp.MANDATORY == followUp )
        {
            sb.append( ", mandatory follow up" );
        }

        return sb.toString();
    }
}
