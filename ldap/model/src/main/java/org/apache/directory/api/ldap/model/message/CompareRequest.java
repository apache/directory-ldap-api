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
package org.apache.directory.api.ldap.model.message;


import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.name.Dn;


/**
 * Compare request protocol message that tests an entry to see if it abides by
 * an attribute value assertion.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface CompareRequest extends SingleReplyRequest, AbandonableRequest
{
    /**
     * Gets the distinguished name of the entry to be compared using the
     * attribute value assertion.
     * 
     * @return the Dn of the compared entry.
     */
    Dn getName();


    /**
     * Sets the distinguished name of the entry to be compared using the
     * attribute value assertion.
     * 
     * @param name the Dn of the compared entry.
     * @return The CompareRequest instance
     */
    CompareRequest setName( Dn name );


    /**
     * Gets the attribute value to use in making the comparison.
     * 
     * @return the attribute value to used in comparison.
     */
    Value<?> getAssertionValue();


    /**
     * Sets the attribute value to use in the comparison.
     * 
     * @param value the attribute value used in comparison.
     * @return The CompareRequest instance
     */
    CompareRequest setAssertionValue( String value );


    /**
     * Sets the attribute value to use in the comparison.
     * 
     * @param value the attribute value used in comparison.
     * @return The CompareRequest instance
     */
    CompareRequest setAssertionValue( byte[] value );


    /**
     * Gets the attribute id use in making the comparison.
     * 
     * @return the attribute id used in comparison.
     */
    String getAttributeId();


    /**
     * Sets the attribute id used in the comparison.
     * 
     * @param attrId the attribute id used in comparison.
     * @return The CompareRequest instance
     */
    CompareRequest setAttributeId( String attrId );


    /**
     * {@inheritDoc}
     */
    @Override
    CompareRequest setMessageId( int messageId );


    /**
     * {@inheritDoc}
     */
    @Override
    CompareRequest addControl( Control control );


    /**
     * {@inheritDoc}
     */
    @Override
    CompareRequest addAllControls( Control[] controls );


    /**
     * {@inheritDoc}
     */
    @Override
    CompareRequest removeControl( Control control );
}
