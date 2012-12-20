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
package org.apache.directory.api.ldap.codec.api;


import java.util.Set;

import org.apache.directory.api.util.Strings;
import org.apache.mina.util.ConcurrentHashSet;


/**
 * An implementation of the BinaryAttributeDetector interface. It's used
 * on the client side to detect if an Attribute is HumanRedable.<br/>
 * One can inject some new attributes, replace the existing list,
 * remove some attributes. <br/>
 * We provide a list of Attributes which are known to be binary :
 * <ul>
 * <li>entryACI</li>
 * <li>prescriptiveACI</li>
 * <li>subentryACI</li>
 * <li>audio</li>
 * <li>javaByteCode</li>
 * <li>javaClassByteCode</li>
 * <li>krb5key</li>
 * <li>m-byteCode</li>
 * <li>privateKey</li>
 * <li>publicKey</li>
 * <li>userPKCS12</li>
 * <li>userSMIMECertificate</li>
 * <li>cACertificate</li>
 * <li>userCertificate</li>
 * <li>authorityRevocationList</li>
 * <li>certificateRevocationList</li>
 * <li>deltaRevocationList</li>
 * <li>crossCertificatePair</li>
 * <li>personalSignature</li>
 * <li>photo</li>
 * <li>jpegPhoto</li>
 * <li>supportedAlgorithms</li>
 * </ul>
 * <br/>
 * In order to reset the detector to get back to those default value, it's enough
 * to call the setBinaryAttributes() with null as a parameter.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DefaultConfigurableBinaryAttributeDetector extends SchemaBinaryAttributeDetector
    implements ConfigurableBinaryAttributeDetector
{
    /** A set of binary Attribute ID */
    private Set<String> binaryAttributes = new ConcurrentHashSet<String>();

    /** A list of all the known binary attributes */
    public final static String[] DEFAULT_BINARY_ATTRIBUTES = new String[]
        {
            "entryACI", // Syntax : ACI Item
            "prescriptiveACI", // Syntax : ACI Item
            "subentryACI", // Syntax : ACI Item
            "audio", // Syntax : Audio
            "javaByteCode", // Syntax : Binary
            "javaClassByteCode", // Syntax : Binary
            "krb5key", // Syntax : Binary
            "m-byteCode", // Syntax : Binary
            "privateKey", // Syntax : Binary
            "publicKey", // Syntax : Binary
            "userPKCS12", // Syntax : Binary
            "userSMIMECertificate", // Syntax : Binary
            "cACertificate", // Syntax : Certificate
            "userCertificate", // Syntax : Certificate
            "authorityRevocationList", // Syntax : Certificate List
            "certificateRevocationList",// Syntax : Certificate List
            "deltaRevocationList", // Syntax : Certificate List
            "crossCertificatePair", // Syntax : Certificate Pair
            "personalSignature", // Syntax : Fax
            "photo", // Syntax : Fax
            "jpegPhoto", // Syntax : JPEG
            "supportedAlgorithms", // Syntax : Supported Algorithm
            "javaSerializedData", // Syntax : Octet String
            "userPassword" // Syntax : Octet String
        };


    /**
     * Creates a new instance of a ConfigurableBinaryAttributeDetector. This will
     * load a set of default attribute ID that are known to be binary.
     */
    public DefaultConfigurableBinaryAttributeDetector()
    {
        setBinaryAttributes( DEFAULT_BINARY_ATTRIBUTES );
    }


    /**
     * {@inheritDoc}
     */
    public boolean isBinary( String attributeId )
    {
        boolean isBinary = super.isBinary( attributeId );

        if ( isBinary )
        {
            return true;
        }

        String attrId = Strings.toLowerCase( attributeId );

        return binaryAttributes.contains( attrId );
    }


    /**
     * {@inheritDoc}
     */
    public void addBinaryAttribute( String... binaryAttributes )
    {
        if ( binaryAttributes != null )
        {
            for ( String binaryAttribute : binaryAttributes )
            {
                String attrId = Strings.toLowerCase( binaryAttribute );
                this.binaryAttributes.add( attrId );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    public void removeBinaryAttribute( String... binaryAttributes )
    {
        if ( binaryAttributes != null )
        {
            for ( String binaryAttribute : binaryAttributes )
            {
                String attrId = Strings.toLowerCase( binaryAttribute );
                this.binaryAttributes.remove( attrId );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    public void setBinaryAttributes( String... binaryAttributes )
    {
        this.binaryAttributes.clear();

        // Special case for 'null'
        if ( binaryAttributes == null )
        {
            // Reseting to the default list of binary attributes
            binaryAttributes = DEFAULT_BINARY_ATTRIBUTES;
        }

        addBinaryAttribute( binaryAttributes );
    }
}
