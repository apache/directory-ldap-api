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
package org.apache.directory.api.ldap.model.message.extended;


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.message.AbstractExtendedResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.util.Strings;


/**
 * An extended operation intended for notifying clients of upcoming
 * disconnection for the Extended response. 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class ExtendedNoDResponse extends AbstractExtendedResponse
{
    /** Declares the Serial Version Uid */
    static final long serialVersionUID = 2L;

    /** The OID of the NotiveOfDisconnect extended operation. */
    public static final String EXTENSION_OID = NoticeOfDisconnect.EXTENSION_OID;

    /** The single instance with unavailable result code. */
    public static final ExtendedNoDResponse UNAVAILABLE = new ExtendedNoDResponse( ResultCodeEnum.UNAVAILABLE );

    /** The single instance with protocolError result code. */
    public static final ExtendedNoDResponse PROTOCOLERROR = new ExtendedNoDResponse( ResultCodeEnum.PROTOCOL_ERROR );

    /** The single instance with strongAuthRequired result code. */
    public static final ExtendedNoDResponse STRONGAUTHREQUIRED = new ExtendedNoDResponse(
        ResultCodeEnum.STRONG_AUTH_REQUIRED );


    /**
     * Creates a new instance of NoticeOfDisconnect.
     * 
     * @param rcode The {@link ResultCodeEnum} value to wrap
     */
    private ExtendedNoDResponse( ResultCodeEnum rcode )
    {
        super( EXTENSION_OID );

        switch ( rcode )
        {
            case UNAVAILABLE:
                break;

            case PROTOCOL_ERROR:
                break;

            case STRONG_AUTH_REQUIRED:
                break;

            default:
                throw new IllegalArgumentException( I18n.err( I18n.ERR_13503_RESULT_CODE_SHOULD_BE_IN, ResultCodeEnum.UNAVAILABLE,
                    ResultCodeEnum.PROTOCOL_ERROR, ResultCodeEnum.STRONG_AUTH_REQUIRED ) );
        }

        super.getLdapResult().setDiagnosticMessage( rcode.toString() + ": The server will disconnect!" );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( rcode );
    }


    // ------------------------------------------------------------------------
    // ExtendedResponse Interface Method Implementations
    // ------------------------------------------------------------------------
    /**
     * Gets the reponse OID specific encoded response values.
     * 
     * @return the response specific encoded response values.
     */
    public byte[] getResponse()
    {
        return Strings.EMPTY_BYTES;
    }
}
