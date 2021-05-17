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


import org.apache.directory.api.ldap.model.exception.LdapSchemaException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;


/**
 * Tests the equals() methods of filter nodes.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class FilterNodeEqualityTest
{
    @Test
    public void testEqualityEquals() throws LdapSchemaException
    {
        EqualityNode<String> eqNode1 = new EqualityNode<String>( "attr1", "test" );
        EqualityNode<String> eqNode2 = new EqualityNode<String>( "attr1", "test" );

        assertEquals( eqNode1, eqNode2, "two exact nodes should be equal" );

        eqNode2 = new EqualityNode<String>( "attr2", "test" );
        assertFalse( eqNode1.equals( eqNode2 ), "different attribute in node should return false on equals()" );

        eqNode2 = new EqualityNode<String>( "attr2", "foobar" );
        assertFalse( eqNode1.equals( eqNode2 ), "different value in node should return false on equals()" );

        PresenceNode presenceNode = new PresenceNode( "attr1" );
        assertFalse( eqNode1.equals( presenceNode ), "two different leaf nodes should not be equal" );
        assertFalse( presenceNode.equals( eqNode1 ), "two different leaf nodes should not be equal" );

        GreaterEqNode<String> greaterEqNode = new GreaterEqNode<String>( "attr1", "test" );
        assertFalse( eqNode1.equals( greaterEqNode ), "two different simple nodes should not be equal" );
        assertFalse( greaterEqNode.equals( eqNode1 ), "two different simple nodes should not be equal" );
    }


    @Test
    public void testGreaterEqEquals() throws LdapSchemaException
    {
        GreaterEqNode<String> greaterEqNode1 = new GreaterEqNode<String>( "attr1", "test" );
        GreaterEqNode<String> greaterEqNode2 = new GreaterEqNode<String>( "attr1", "test" );

        assertEquals( greaterEqNode1, greaterEqNode2, "two exact nodes should be equal" );

        greaterEqNode2 = new GreaterEqNode<String>( "attr2", "test" );
        assertFalse( greaterEqNode1
            .equals( greaterEqNode2 ), "different attribute in node should return false on equals()" );

        greaterEqNode2 = new GreaterEqNode<String>( "attr2", "foobar" );
        assertFalse( greaterEqNode1.equals( greaterEqNode2 ), "different value in node should return false on equals()" );
    }


    @Test
    public void testLessEqEquals() throws LdapSchemaException
    {
        LessEqNode<String> lessEqNode1 = new LessEqNode<String>( "attr1", "test" );
        LessEqNode<String> lessEqNode2 = new LessEqNode<String>( "attr1", "test" );

        assertEquals( lessEqNode1, lessEqNode2, "two exact nodes should be equal" );

        lessEqNode2 = new LessEqNode<String>( "attr2", "test" );
        assertFalse( lessEqNode1.equals( lessEqNode2 ), "different attribute in node should return false on equals()" );

        lessEqNode2 = new LessEqNode<String>( "attr2", "foobar" );
        assertFalse( lessEqNode1.equals( lessEqNode2 ), "different value in node should return false on equals()" );
    }


    @Test
    public void testApproximateEqEquals()
    {
        ApproximateNode<String> approximateNode1 = new ApproximateNode<String>( "attr1", "test" );
        ApproximateNode<String> approximateNode2 = new ApproximateNode<String>( "attr1", "test" );

        assertEquals( approximateNode1, approximateNode2, "two exact nodes should be equal" );

        approximateNode2 = new ApproximateNode<String>( "attr2", "test" );
        assertFalse( approximateNode1
            .equals( approximateNode2 ), "different attribute in node should return false on equals()" );

        approximateNode2 = new ApproximateNode<String>( "attr2", "foobar" );
        assertFalse( approximateNode1
            .equals( approximateNode2 ), "different value in node should return false on equals()" );
    }


    @Test
    public void testPresenceEquals()
    {
        PresenceNode presenceNode1 = new PresenceNode( "attr1" );
        PresenceNode presenceNode2 = new PresenceNode( "attr1" );

        assertEquals( presenceNode1, presenceNode2, "two exact presence nodes on same attribute should be equal" );

        presenceNode2 = new PresenceNode( "attr2" );
        assertFalse( presenceNode1.equals( presenceNode2 ), "presence nodes on different attributes should not be equal" );
    }


    @Test
    public void testSubstringEquals()
    {
    }
}
