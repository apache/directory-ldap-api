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
package org.apache.directory.api.ldap.model.filter;


/**
 * An empty class used for the (ObjectClass=*) node.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public final class ObjectClassNode extends AbstractExprNode
{
    /** A static instance of this node */
    public static final ExprNode OBJECT_CLASS_NODE = new ObjectClassNode();


    /**
     * Creates a new instance of ObjectClassNode.
     */
    private ObjectClassNode()
    {
        super( AssertionType.OBJECTCLASS );
    }


    /**
     * {@inheritDoc}
     * 
     * This implementation always returns true.
     */
    @Override
    public boolean isLeaf()
    {
        return true;
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
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return "All";
    }
}
