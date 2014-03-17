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

import org.apache.directory.api.asn1.AbstractAsn1Object;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PwdModifyResponse;


/**
 * A PasswordModifyResponse class, as described in RFC 3062
 * 
 * <pre>
 *  PasswdModifyResponseValue ::= SEQUENCE {
 *    genPasswd       [0]     OCTET STRING OPTIONAL }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordModifyResponse extends AbstractAsn1Object
{
    /** The encapsulated response */
    private PwdModifyResponse pwdModifyResponse;


    /**
     * Creates an instance of a PasswordModifyResponse
     * @param pwdModifyResponse The encapsulated response
     */
    public PasswordModifyResponse( PwdModifyResponse pwdModifyResponse )
    {
        this.pwdModifyResponse = pwdModifyResponse;
    }

    /** stores the length of the request*/
    private int requestLength = 0;


    /**
     * {@inheritDoc}
     */
    public int computeLength()
    {
        requestLength = 0;

        if ( pwdModifyResponse.getGenPassword() != null )
        {
            int len = pwdModifyResponse.getGenPassword().length;
            requestLength = 1 + BerValue.getNbBytes( len ) + len;
        }

        return 1 + BerValue.getNbBytes( requestLength ) + requestLength;
    }


    /**
     * {@inheritDoc}
     */
    public ByteBuffer encode() throws EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( computeLength() );

        bb.put( UniversalTag.SEQUENCE.getValue() );
        bb.put( BerValue.getBytes( requestLength ) );

        if ( pwdModifyResponse.getGenPassword() != null )
        {
            byte[] userIdentity = pwdModifyResponse.getGenPassword();
            bb.put( ( byte ) PasswordModifyRequestConstants.USER_IDENTITY_TAG );
            bb.put( TLV.getBytes( userIdentity.length ) );
            bb.put( userIdentity );
        }

        return bb;
    }


    /**
     * @return The internal PwdModifyResponse object
     */
    public PwdModifyResponse getPwdModifyResponse()
    {
        return pwdModifyResponse;
    }


    /**
     * @see Object#toString()
     */
    public String toString()
    {
        return pwdModifyResponse.toString();
    }
}
