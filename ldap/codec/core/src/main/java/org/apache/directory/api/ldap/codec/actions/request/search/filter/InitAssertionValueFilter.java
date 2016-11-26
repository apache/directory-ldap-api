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
package org.apache.directory.api.ldap.codec.actions.request.search.filter;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.ldap.codec.AttributeValueAssertion;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.decorators.SearchRequestDecorator;
import org.apache.directory.api.ldap.codec.search.AttributeValueAssertionFilter;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to initialize the Assertion Value filter
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class InitAssertionValueFilter extends GrammarAction<LdapMessageContainer<SearchRequestDecorator>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( InitAssertionValueFilter.class );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = LOG.isDebugEnabled();


    /**
     * Instantiates a new init assertion value filter action.
     */
    public InitAssertionValueFilter()
    {
        super( "Initialize Assertion Value filter" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( LdapMessageContainer<SearchRequestDecorator> container ) throws DecoderException
    {
        SearchRequestDecorator searchRequestDecorator = container.getMessage();

        TLV tlv = container.getCurrentTLV();

        // The value can be null.
        byte[] assertion = tlv.getValue().getData();
        
        AttributeValueAssertionFilter terminalFilter = ( AttributeValueAssertionFilter )
            searchRequestDecorator.getTerminalFilter();
        AttributeValueAssertion attributeValueAssertion = terminalFilter.getAssertion();

        if ( assertion == null )
        {
            attributeValueAssertion.setAssertion( Strings.EMPTY_BYTES );
        }
        else
        {
            attributeValueAssertion.setAssertion( assertion );
        }

        // We now have to get back to the nearest filter which is
        // not terminal.
        searchRequestDecorator.unstackFilters( container );

        if ( IS_DEBUG )
        {
            LOG.debug( "Initialize Assertion Value filter" );
        }
    }
}
