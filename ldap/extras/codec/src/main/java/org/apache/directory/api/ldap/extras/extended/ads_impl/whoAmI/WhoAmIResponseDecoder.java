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
package org.apache.directory.api.ldap.extras.extended.ads_impl.whoAmI;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Container;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIResponse;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIResponseImpl;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * 
 * A decoder for WhoAmIRequest.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class WhoAmIResponseDecoder extends Asn1Decoder
{
    /** logger */
    private static final Logger LOG = LoggerFactory.getLogger( WhoAmIResponseDecoder.class );

    
    /**
     * {@inheritDoc}
     */
    @Override
    public void decode( ByteBuffer stream, Asn1Container container ) throws DecoderException
    {
        ( ( WhoAmIResponseContainer ) container ).setWhoAmIResponse( 
            ( WhoAmIResponseDecorator ) decode( stream.array() ) );
    }


    /**
     * Decode a PDU which must contain a WhoAmIRequest extended operation.
     * Note that the stream of bytes much contain a full PDU, not a partial one.
     * 
     * @param stream The bytes to be decoded
     * @return a WhoAmIRequest object
     * @throws org.apache.directory.api.asn1.DecoderException If the decoding failed
     */
    public WhoAmIResponse decode( byte[] data ) throws DecoderException
    {
        WhoAmIResponseDecorator whoAmIResponse = new WhoAmIResponseDecorator(
            LdapApiServiceFactory.getSingleton(), new WhoAmIResponseImpl() );

        if ( Strings.isEmpty( data ) )
        {
            whoAmIResponse.setAuthzId( null );
        }
        else
        {
            switch ( data.length )
            {
                case 0:
                    // Error
                case 1:
                    // Error
                    String msg = I18n.err( I18n.ERR_08226_AUTHZID_TOO_SHORT_MISSING_U_OR_DN );
                    LOG.error( msg );
                    throw new DecoderException( msg );

                case 2 :
                    if ( ( data[0] == 'u' ) && ( data[1] == ':' ) )
                    {
                        whoAmIResponse.setAuthzId( data );
                        whoAmIResponse.setUserId( Strings.utf8ToString( data, 3, data.length - 3 ) );
                    }
                    else
                    {
                        msg = I18n.err( I18n.ERR_08227_AUTHZID_MUST_START_WITH_U_OR_DN, Strings.utf8ToString( data ) );
                        LOG.error( msg );
                        throw new DecoderException( msg );
                    }
                    
                    break;
                    
                default :
                    switch ( data[0] )
                    {
                        case 'u' :
                            if ( data[1] == ':' )
                            {
                                whoAmIResponse.setAuthzId( data );
                                whoAmIResponse.setUserId( Strings.utf8ToString( data, 3, data.length - 3 ) );
                            }
                            else
                            {
                                msg = I18n.err( I18n.ERR_08227_AUTHZID_MUST_START_WITH_U_OR_DN, Strings.utf8ToString( data ) );
                                LOG.error( msg );
                                throw new DecoderException( msg );
                            }
                            
                            break;
                            
                        case 'd' :
                            if ( ( data[1] == 'n' ) && ( data[2] == ':' ) )
                            {
                                // Check that the remaining bytes are a valid DN
                                if ( Dn.isValid( Strings.utf8ToString( data, 3, data.length - 3 ) ) )
                                {
                                    whoAmIResponse.setAuthzId( data );
                                    
                                    try
                                    {
                                        whoAmIResponse.setDn( new Dn( Strings.utf8ToString( data, 3, data.length - 3 ) ) );
                                    }
                                    catch ( LdapInvalidDnException e )
                                    {
                                        // Should never happen
                                    }
                                }
                                else
                                {
                                    msg = I18n.err( I18n.ERR_08227_AUTHZID_MUST_START_WITH_U_OR_DN, Strings.utf8ToString( data ) );
                                    LOG.error( msg );
                                    throw new DecoderException( msg );
                                }
                            }
                            else
                            {
                                msg = I18n.err( I18n.ERR_08227_AUTHZID_MUST_START_WITH_U_OR_DN, Strings.utf8ToString( data ) );
                                LOG.error( msg );
                                throw new DecoderException( msg );
                            }
                            
                            break;

                        default :
                            msg = I18n.err( I18n.ERR_08227_AUTHZID_MUST_START_WITH_U_OR_DN, Strings.utf8ToString( data ) );
                            LOG.error( msg );
                            throw new DecoderException( msg );
                    }
                    
                    break;
            }
        }

        return whoAmIResponse;
    }
}
