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
package org.apache.directory.shared.ldap.aci.protectedItem;

import java.util.Set;

/**
 * All attribute value information pertaining to specific attributes.
 */
public class AllAttributeValuesItem extends AbstractAttributeTypeProtectedItem
{
    /**
     * Creates a new instance.
     * 
     * @param attributeTypes the collection of attribute IDs.
     */
    public AllAttributeValuesItem( Set<String> attributeTypes )
    {
        super( attributeTypes );
    }


    public String toString()
    {
        return "allAttributeValues " + super.toString();
    }
}

