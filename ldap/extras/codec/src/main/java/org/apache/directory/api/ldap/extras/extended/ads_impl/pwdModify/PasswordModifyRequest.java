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
package org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.Asn1Object;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PwdModifyRequest;


/**
 * An extended operation to proceed a pwdModifyRequest operation, as described 
 * in RFC 3062
 * 
 * <pre>
 *  PasswdModifyRequestValue ::= SEQUENCE {
 *    userIdentity    [0]  OCTET STRING OPTIONAL
 *    oldPasswd       [1]  OCTET STRING OPTIONAL
 *    newPasswd       [2]  OCTET STRING OPTIONAL }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordModifyRequest implements Asn1Object
{
    /** The encapsulated request */
    private PwdModifyRequest pwdModifyRequest;


    /**
     * Creates an instance of a PasswordModifyRequest
     * @param pwdModifyRequest The encapsulated request
     */
    public PasswordModifyRequest( PwdModifyRequest pwdModifyRequest )
    {
        this.pwdModifyRequest = pwdModifyRequest;
    }

    /** stores the length of the request*/
    private int requestLength = 0;


    /**
     * {@inheritDoc}
     */
    public int computeLength()
    {
        requestLength = 0;

        if ( pwdModifyRequest.getUserIdentity() != null )
        {
            int len = pwdModifyRequest.getUserIdentity().length;
            requestLength = 1 + BerValue.getNbBytes( len ) + len;
        }

        if ( pwdModifyRequest.getOldPassword() != null )
        {
            int len = pwdModifyRequest.getOldPassword().length;
            requestLength += 1 + BerValue.getNbBytes( len ) + len;
        }

        if ( pwdModifyRequest.getNewPassword() != null )
        {
            int len = pwdModifyRequest.getNewPassword().length;
            requestLength += 1 + BerValue.getNbBytes( len ) + len;
        }

        return 1 + BerValue.getNbBytes( requestLength ) + requestLength;
    }


    /**
     * {@inheritDoc}
     */
    public ByteBuffer encode() throws EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( computeLength() );

        return encode( bb );
    }


    /**
     * {@inheritDoc}
     */
    public ByteBuffer encode( ByteBuffer bb ) throws EncoderException
    {
        if ( bb == null )
        {
            throw new EncoderException( "Null ByteBuffer, cannot encode " + this );
        }

        bb.put( UniversalTag.SEQUENCE.getValue() );
        bb.put( BerValue.getBytes( requestLength ) );

        if ( pwdModifyRequest.getUserIdentity() != null )
        {
            byte[] userIdentity = pwdModifyRequest.getUserIdentity();
            bb.put( ( byte ) PasswordModifyRequestConstants.USER_IDENTITY_TAG );
            bb.put( TLV.getBytes( userIdentity.length ) );
            bb.put( userIdentity );
        }

        if ( pwdModifyRequest.getOldPassword() != null )
        {
            byte[] oldPassword = pwdModifyRequest.getOldPassword();
            bb.put( ( byte ) PasswordModifyRequestConstants.OLD_PASSWORD_TAG );
            bb.put( TLV.getBytes( oldPassword.length ) );
            bb.put( oldPassword );
        }

        if ( pwdModifyRequest.getNewPassword() != null )
        {
            byte[] newPassword = pwdModifyRequest.getNewPassword();
            bb.put( ( byte ) PasswordModifyRequestConstants.NEW_PASSWORD_TAG );
            bb.put( TLV.getBytes( newPassword.length ) );
            bb.put( newPassword );
        }

        return bb;
    }


    /**
     * @return the pwdModifyRequest
     */
    public PwdModifyRequest getPwdModifyRequest()
    {
        return pwdModifyRequest;
    }


    /**
     * @see Object#toString()
     */
    public String toString()
    {
        return pwdModifyRequest.toString();
    }
}
