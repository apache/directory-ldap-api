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
package org.apache.directory.api.ldap.extras.extended;


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.message.ExtendedResponseImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.util.Strings;


/**
 * The RFC 3062 PwdModify response :
 * 
 * <pre>
 * PasswdModifyResponseValue ::= SEQUENCE {
 *    genPasswd       [0]     OCTET STRING OPTIONAL }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PwdModifyResponseImpl extends ExtendedResponseImpl implements PwdModifyResponse
{
    /** The generated password */
    private byte[] genPassword;


    /**
     * Create a new instance for the PwdModify response
     * @param messageId The Message ID
     * @param rcode The result code
     */
    public PwdModifyResponseImpl( int messageId, ResultCodeEnum rcode )
    {
        super( messageId, EXTENSION_OID );

        switch ( rcode )
        {
            case SUCCESS:
                break;

            case OPERATIONS_ERROR:
                break;

            case INSUFFICIENT_ACCESS_RIGHTS:
                break;

            default:
                throw new IllegalArgumentException( I18n.err( I18n.ERR_04166, ResultCodeEnum.SUCCESS,
                    ResultCodeEnum.OPERATIONS_ERROR, ResultCodeEnum.INSUFFICIENT_ACCESS_RIGHTS ) );
        }

        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( rcode );
    }


    /**
     * Instantiates a new password Modify response.
     *
     * @param messageId the message id
     */
    public PwdModifyResponseImpl( int messageId )
    {
        super( messageId, EXTENSION_OID );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
    }


    /**
     * Instantiates a new password Modify response.
     */
    public PwdModifyResponseImpl()
    {
        super( EXTENSION_OID );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
    }


    /**
     * {@inheritDoc}
     */
    public byte[] getGenPassword()
    {
        return genPassword;
    }


    /**
     * Set the generated Password
     * @param genPassword The generated password
     */
    public void setGenPassword( byte[] genPassword )
    {
        this.genPassword = genPassword;
    }


    /**
     * @see Object#toString()
     */
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "PwdModifyResponse :" );
        sb.append( "\n    genPassword : " );

        if ( genPassword != null )
        {
            sb.append( Strings.utf8ToString( genPassword ) );
        }
        else
        {
            sb.append( "null" );
        }

        return sb.toString();
    }
}
