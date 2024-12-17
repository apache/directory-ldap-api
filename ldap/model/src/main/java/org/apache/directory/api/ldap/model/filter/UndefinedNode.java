/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.ldap.model.filter;

/**
 * An empty class used for Undefined Nodes.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public final class UndefinedNode extends AbstractExprNode
{
    /** A static instance of this node */
    public static final UndefinedNode UNDEFINED_NODE = new UndefinedNode( "" );

    /** attribute on which this leaf is based */
    protected String attribute;


    /**
     * Creates a new instance of UndefinedNode.
     * 
     * @param attribute The leaf's attribute
     */
    public UndefinedNode( String attribute )
    {
        super( AssertionType.UNDEFINED );

        this.attribute = attribute;
    }


    /**
     * {@inheritDoc}
     * 
     * This implementation always returns false.
     */
    @Override
    public boolean isLeaf()
    {
        return false;
    }


    /**
     * {@inheritDoc}
     * 
     * This implementation always returns null.
     */
    @Override
    public Object accept( FilterVisitor visitor )
    {
        return null;
    }


    /**
     * Tells if this Node is Schema aware.
     * 
     * @return true if the Node is SchemaAware
     */
    @Override
    public boolean isSchemaAware()
    {
        return false;
    }

    
    public void setAttribute( String attribute )
    {
        this.attribute = attribute;
    }
    

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return "(Undefined:" + attribute + ")";
    }
}
