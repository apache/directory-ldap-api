/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.ldap.extras.extended.certGeneration;


import org.apache.directory.api.ldap.model.message.ExtendedRequest;


/**
 * The interface for a certificate generation request extended operation.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface CertGenerationRequest extends ExtendedRequest
{
    /** The OID for the Certificate Generation extended operation request. */
    String EXTENSION_OID = "1.3.6.1.4.1.18060.0.1.8";


    /** 
     * Get the Target DN for the certificate storage
     * 
     * @return The target DN 
     **/
    String getTargetDN();


    /**
     * Sets the target DN
     * 
     * @param targetDN The target DN
     */
    void setTargetDN( String targetDN );


    /**
     * @return The issuer's DN
     */
    String getIssuerDN();


    /**
     * Sets the issuer's DN
     *  
     * @param issuerDN the issuer's DN 
     */
    void setIssuerDN( String issuerDN );


    /**
     * @return The subect's DN
     */
    String getSubjectDN();


    /**
     * Sets the subect's DN
     * 
     * @param subjectDN The subect's DN
     */
    void setSubjectDN( String subjectDN );


    /**
     * @return The Key algorithm 
     */
    String getKeyAlgorithm();


    /**
     * Sets the Key algorithm
     * @param keyAlgorithm The Key algorithm
     */
    void setKeyAlgorithm( String keyAlgorithm );

}