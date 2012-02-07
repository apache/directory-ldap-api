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
package org.apache.directory.shared.ldap.codec.api;

import java.util.Set;

import org.apache.directory.shared.util.Strings;
import org.apache.mina.util.ConcurrentHashSet;

/**
 * An implementation of the BinaryAttributeDetector interface. It's not
 * schema aware, so it only uses the list of binary Attributes.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class NoSchemaBinaryAttributeDetector implements BinaryAttributeDetector
{
    /** A set of binary Attribute ID */
    private Set<String> binaryAttributes = new ConcurrentHashSet<String>();

    /** A set of binary Syntax ID */
    private Set<String> binarySyntaxes = new ConcurrentHashSet<String>();
    
    
    /**
     * Creates a new instance of BinaryAttributeDetector. It's not schema aware
     */
    public NoSchemaBinaryAttributeDetector()
    {
    }
    
    
    /**
     * {@inheritDoc}
     */
    public boolean isBinary( String attributeId )
    {
        String attrId = Strings.toLowerCase( attributeId );

        if ( attrId.endsWith( ";binary" ) )
        {
            return true;
        }

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
    public void setBinaryAttributes( Set<String> binaryAttributes )
    {
        if ( binaryAttributes != null )
        {
            this.binaryAttributes.clear();
            
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
    public void addBinarySyntaxes( String... binarySyntaxes )
    {
        if ( binarySyntaxes != null )
        {
            for ( String binarySyntax : binarySyntaxes )
            {
                String syntaxId = Strings.toLowerCase( binarySyntax );
                this.binarySyntaxes.add( syntaxId );
            }
        }
    }
    

    /**
     * {@inheritDoc}
     */
    public void setBinarySyntaxes( Set<String> binarySyntaxes )
    {
        if ( binarySyntaxes != null )
        {
            this.binarySyntaxes.clear();
            
            for ( String binarySyntax : binarySyntaxes )
            {
                String syntaxId = Strings.toLowerCase( binarySyntax );
                this.binarySyntaxes.add( syntaxId );
            }
        }
    }
    

    /**
     * {@inheritDoc}
     */
    public void removeBinarySyntaxes( String... binarySyntaxes )
    {
        if ( binarySyntaxes != null )
        {
            for ( String binarySyntax : binarySyntaxes )
            {
                String syntaxId = Strings.toLowerCase( binarySyntax );
                this.binarySyntaxes.remove( syntaxId );
            }
        }
    }
}
