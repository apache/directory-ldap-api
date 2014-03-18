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
package org.apache.directory.api.ldap.extras.extended.ads_impl.certGeneration;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.Asn1Object;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.ldap.extras.extended.certGeneration.CertGenerationRequest;
import org.apache.directory.api.util.Strings;


/**
 * 
 * An extended operation for generating a public key Certificate.
 * <pre>
 *   CertGenerateObject ::= SEQUENCE
 *   {
 *      targetDN        IA5String,
 *      issuerDN        IA5String,
 *      subjectDN       IA5String,
 *      keyAlgorithm    IA5String
 *   }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CertGeneration implements Asn1Object
{
    private CertGenerationRequest request;


    public CertGeneration( CertGenerationRequest request )
    {
        this.request = request;
    }

    /** stores the length of the request*/
    private int requestLength = 0;


    /**
     * {@inheritDoc}
     */
    public int computeLength()
    {
        int len = Strings.getBytesUtf8( request.getTargetDN() ).length;
        requestLength = 1 + BerValue.getNbBytes( len ) + len;

        len = Strings.getBytesUtf8( request.getIssuerDN() ).length;
        requestLength += 1 + BerValue.getNbBytes( len ) + len;

        len = Strings.getBytesUtf8( request.getSubjectDN() ).length;
        requestLength += 1 + BerValue.getNbBytes( len ) + len;

        len = Strings.getBytesUtf8( request.getKeyAlgorithm() ).length;
        requestLength += 1 + BerValue.getNbBytes( len ) + len;

        return 1 + BerValue.getNbBytes( requestLength ) + requestLength;
    }


    /**
     * {@inheritDoc}
     */
    public ByteBuffer encode() throws EncoderException
    {
        // Allocate the bytes buffer.
        ByteBuffer bb = ByteBuffer.allocate( computeLength() );

        return encode( bb );
    }


    public ByteBuffer encode( ByteBuffer bb ) throws EncoderException
    {
        if ( bb == null )
        {
            throw new EncoderException( "Null ByteBuffer, cannot encode " + this );
        }

        bb.put( UniversalTag.SEQUENCE.getValue() );
        bb.put( BerValue.getBytes( requestLength ) );

        BerValue.encode( bb, request.getTargetDN() );
        BerValue.encode( bb, request.getIssuerDN() );
        BerValue.encode( bb, request.getSubjectDN() );
        BerValue.encode( bb, request.getKeyAlgorithm() );

        return bb;
    }
}
