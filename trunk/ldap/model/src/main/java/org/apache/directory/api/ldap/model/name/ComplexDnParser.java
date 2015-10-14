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


import java.io.StringReader;
import java.util.List;

import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;


/**
 * A Dn parser that is able to parse complex DNs. This is an Antlr based parser.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
/* No protection*/class ComplexDnParser
{

    /**
     * Parses an Dn.
     * 
     * @param name the string representation of the distinguished name
     * @param rdns the (empty) list where parsed RDNs are put to
     * 
     * @throws LdapInvalidDnException the invalid name exception
     */
    /* No protection*/void parseDn( String name, List<Rdn> rdns ) throws LdapInvalidDnException
    {
        AntlrDnParser dnParser = new AntlrDnParser( new AntlrDnLexer( new StringReader( name ) ) );

        try
        {
            dnParser.relativeDistinguishedNames( rdns );
        }
        catch ( Exception e )
        {
            throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, e.getMessage(), e );
        }
    }


    /**
     * Parses an Rdn.
     * 
     * @param name the string representationof the relative distinguished name
     * @param rdn the (empty) Rdn where parsed ATAVs are put to
     * 
     * @throws LdapInvalidDnException the invalid name exception
     */
    /* No protection*/void parseRdn( String name, Rdn rdn ) throws LdapInvalidDnException
    {
        AntlrDnParser dnParser = new AntlrDnParser( new AntlrDnLexer( new StringReader( name ) ) );

        try
        {
            dnParser.relativeDistinguishedName( rdn );
        }
        catch ( Exception e )
        {
            throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, e.getMessage(), e );
        }
    }
}
