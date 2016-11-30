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
package org.apache.directory.api.ldap.extras.extended.storedProcedure;


import java.util.List;

import org.apache.directory.api.ldap.model.message.ExtendedRequest;


/**
 * An extended operation requesting the server to execute a stored procedure.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface StoredProcedureRequest extends ExtendedRequest
{
    /** The OID for the stored procedure extended operation request. */
    String EXTENSION_OID = "1.3.6.1.4.1.18060.0.1.6";


    /**
     * Gets the language.
     *
     * @return the language
     */
    String getLanguage();


    /**
     * Sets the language.
     *
     * @param language the new language
     */
    void setLanguage( String language );


    /**
     * @return The byte[] containing the procedure's bytecode
     */
    byte[] getProcedure();


    /**
     * @param procedure The procedure's bytecode
     */
    void setProcedure( byte[] procedure );


    /**
     * Gets the procedure specification.
     *
     * @return the procedure specification
     */
    String getProcedureSpecification();


    /**
     * Size.
     *
     * @return the procedure's bytcode size
     */
    int size();


    /**
     * Gets the parameter type.
     *
     * @param index the index
     * @return the parameter type
     */
    Object getParameterType( int index );


    /**
     * Gets the java parameter type.
     *
     * @param index the index
     * @return the java parameter type
     */
    Class<?> getJavaParameterType( int index );


    /**
     * Gets the parameter value.
     *
     * @param index the index
     * @return the parameter value
     */
    Object getParameterValue( int index );


    /**
     * Gets the java parameter value.
     *
     * @param index the index
     * @return the java parameter value
     */
    Object getJavaParameterValue( int index );


    /**
     * Adds the parameter.
     *
     * @param type the type
     * @param value the value
     */
    void addParameter( Object type, Object value );


    /**
     * Adds a parameter
     * 
     * @param parameter The parameter to add
     */
    void addParameter( StoredProcedureParameter parameter );


    /**
     * @return The list of parameters for this stored procedure
     */
    List<StoredProcedureParameter> getParameters();
}