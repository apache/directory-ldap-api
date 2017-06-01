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
package org.apache.directory.api.ldap.model.name;


/**
 * Utility class used to manipulate Dn or Rdn elements.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class DnUtils
{
    private DnUtils()
    {
    }


    /**
     * Gets the attributeType of a RDN (the left part of the RDN). The RDN is supposed
     * to contain only one AVA.
     *
     * @param rdn the RDN
     * @return the attributeType 
     */
    public static String getRdnAttributeType( String rdn )
    {
        int index = rdn.indexOf( '=' );
        return rdn.substring( 0, index );
    }


    /**
     * Gets the value of a RDN ( the right part of the RDN). The RDN is supposed
     * to contain only one AVA.
     *
     * @param rdn the RDN
     * @return the value of tpart of the RDN
     */
    public static String getRdnValue( String rdn )
    {
        int index = rdn.indexOf( '=' );
        return rdn.substring( index + 1, rdn.length() );
    }
}
