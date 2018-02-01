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
package org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction.controls.actions;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction.controls.ControlsContainer;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used add a new control. We store its OID.
 * <pre>
 * Control ::= SEQUENCE {
 *     controlType             LDAPOID,
 *     ...
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AddControl extends GrammarAction<ControlsContainer>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( AddControl.class );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = LOG.isDebugEnabled();


    /**
     * Instantiates a new AddControl action.
     */
    public AddControl()
    {
        super( "Add a new control" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( ControlsContainer container ) throws DecoderException
    {
        TLV tlv = container.getCurrentTLV();

        // Store the type
        // We have to handle the special case of a 0 length OID
        if ( tlv.getLength() == 0 )
        {
            String msg = I18n.err( I18n.ERR_04097_NULL_CONTROL_OID );
            LOG.error( msg );

            // This will generate a PROTOCOL_ERROR
            throw new DecoderException( msg );
        }

        byte[] value = tlv.getValue().getData();
        String oidValue = Strings.asciiBytesToString( value );

        // The OID is encoded as a String, not an Object Id
        if ( !Oid.isOid( oidValue ) )
        {
            String msg = I18n.err( I18n.ERR_04098_INVALID_CONTROL_OID, oidValue );
            LOG.error( msg );

            // This will generate a PROTOCOL_ERROR
            throw new DecoderException( msg );
        }

        CodecControl<?> control = container.getLdapCodecService().newControl( oidValue );

        container.setCurrentControl( control );
        container.addControl( control );
        
        // We can have an END transition
        container.setGrammarEndAllowed( true );

        if ( IS_DEBUG )
        {
            LOG.debug( "Control OID : {}", oidValue );
        }
    }
}
