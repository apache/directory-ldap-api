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


/**
 * An interface used to abstract the means to detect whether or not an attribute
 * identifier/descriptor represents a binary attributeType.
 */
public interface ConfigurableBinaryAttributeDetector extends BinaryAttributeDetector
{
    /**
     * Add some binary Attributes Id to the list of attributes
     * 
     * @param binaryAttributes The added binary attributes Id
     */
    void addBinaryAttribute( String... binaryAttributes );


    /**
     * Remove some binary Attributes Id from the list of attributes
     * 
     * @param binaryAttributes The binary attributes Id to remove
     */
    void removeBinaryAttribute( String... binaryAttributes );


    /**
     * Inject a new set of binary attributes that will replace the old one.
     * If one inject a null set of attributes, the list of attributes will be
     * cleared, and reset to the default list of binary attributes. If one
     * injects an empty String array, then all the attributes will be removed
     * from the list, and we won't inject the default attributes into it.
     * 
     * @param binaryAttributes The new set of binary attributes
     */
    void setBinaryAttributes( String... binaryAttributes );
}
