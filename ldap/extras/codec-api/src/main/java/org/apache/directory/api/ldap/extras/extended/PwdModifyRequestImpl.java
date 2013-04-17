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


import org.apache.directory.api.ldap.model.message.AbstractExtendedRequest;
import org.apache.directory.api.util.Strings;


/**
 * The RFC 3062 PwdModify request :
 * 
 * <pre>
 *   PasswdModifyRequestValue ::= SEQUENCE {
 *    userIdentity    [0]  OCTET STRING OPTIONAL
 *    oldPasswd       [1]  OCTET STRING OPTIONAL
 *    newPasswd       [2]  OCTET STRING OPTIONAL }
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PwdModifyRequestImpl extends AbstractExtendedRequest<PwdModifyResponse> implements PwdModifyRequest
{
    /** The user identity */
    private byte[] userIdentity;

    /** The previous password */
    private byte[] oldPassword;

    /** The new password */
    private byte[] newPassword;


    /**
     * Create a new instance of the PwdModifyRequest extended operation
     */
    public PwdModifyRequestImpl()
    {
    }


    /**
     * Create a new instance of the PwdModifyRequest extended operation
     * 
     * @param messageId The message ID
     */
    public PwdModifyRequestImpl( int messageId )
    {
    }


    /**
     * {@inheritDoc}
     */
    public byte[] getUserIdentity()
    {
        return userIdentity;
    }


    /**
     * @param userIdentity the userIdentity to set
     */
    public void setUserIdentity( byte[] userIdentity )
    {
        this.userIdentity = userIdentity;
    }


    /**
     * {@inheritDoc}
     */
    public byte[] getOldPassword()
    {
        return oldPassword;
    }


    /**
     * @param oldPassword the oldPassword to set
     */
    public void setOldPassword( byte[] oldPassword )
    {
        this.oldPassword = oldPassword;
    }


    /**
     * {@inheritDoc}
     */
    public byte[] getNewPassword()
    {
        return newPassword;
    }


    /**
     * @param newPassword the newPassword to set
     */
    public void setNewPassword( byte[] newPassword )
    {
        this.newPassword = newPassword;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PwdModifyResponse getResultResponse()
    {
        if ( response == null )
        {
            response = new PwdModifyResponseImpl();
        }

        return response;
    }


    /**
     * @see Object#toString()
     */
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "PwdModifyRequest :" );
        sb.append( "\n    UserIdentity : " );

        if ( userIdentity != null )
        {
            sb.append( Strings.utf8ToString( userIdentity ) );
        }
        else
        {
            sb.append( "null" );
        }

        sb.append( "\n    oldPassword : " );

        if ( oldPassword != null )
        {
            sb.append( Strings.utf8ToString( oldPassword ) );
        }
        else
        {
            sb.append( "null" );
        }

        sb.append( "\n    newPassword : " );

        if ( newPassword != null )
        {
            sb.append( Strings.utf8ToString( newPassword ) );
        }
        else
        {
            sb.append( "null" );
        }

        return sb.toString();
    }
}
