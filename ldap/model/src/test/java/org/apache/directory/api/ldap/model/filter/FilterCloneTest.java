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


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.text.ParseException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests the FilterParserImpl class.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class FilterCloneTest
{
    @Test
    public void testItemFilter() throws ParseException
    {
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( null, "(ou~=people)" );
        // just check that it doesn't throw for now
        node = ( SimpleNode<?> ) node.clone();
        assertEquals( "ou", node.getAttribute() );
        assertEquals( "people", node.getValue().getString() );
        assertTrue( node instanceof ApproximateNode );
    }


    @Test
    public void testAndFilter() throws ParseException
    {
        BranchNode node = ( BranchNode ) FilterParser.parse( null, "(&(ou~=people)(age>=30))" );
        // just check that it doesn't throw for now
        node = ( BranchNode ) node.clone();
        assertEquals( 2, node.getChildren().size() );
        assertTrue( node instanceof AndNode );
    }


    @Test
    public void testAndFilterOneChildOnly() throws ParseException
    {
        BranchNode node = ( BranchNode ) FilterParser.parse( null, "(&(ou~=people))" );
        // just check that it doesn't throw for now
        node = ( BranchNode ) node.clone();
        assertEquals( 1, node.getChildren().size() );
        assertTrue( node instanceof AndNode );
    }


    @Test
    public void testOrFilter() throws ParseException
    {
        BranchNode node = ( BranchNode ) FilterParser.parse( null, "(|(ou~=people)(age>=30))" );
        // just check that it doesn't throw for now
        node = ( BranchNode ) node.clone();
        assertEquals( 2, node.getChildren().size() );
        assertTrue( node instanceof OrNode );
    }


    @Test
    public void testOrFilterOneChildOnly() throws ParseException
    {
        BranchNode node = ( BranchNode ) FilterParser.parse( null, "(|(age>=30))" );
        // just check that it doesn't throw for now
        node = ( BranchNode ) node.clone();
        assertEquals( 1, node.getChildren().size() );
        assertTrue( node instanceof OrNode );
    }


    @Test
    public void testNotFilter() throws ParseException
    {
        BranchNode node = ( BranchNode ) FilterParser.parse( null, "(!(&(ou~= people)(age>=30)))" );
        // just check that it doesn't throw for now
        node = ( BranchNode ) node.clone();
        assertEquals( 1, node.getChildren().size() );
        assertTrue( node instanceof NotNode );
    }


    @Test
    public void testOptionAndEscapesFilter() throws ParseException
    {
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( null, "(ou;lang-de>=\\23\\42asdl fkajsd)" );
        // just check that it doesn't throw for now
        node = ( SimpleNode<?> ) node.clone();
        assertEquals( "ou;lang-de", node.getAttribute() );
        assertEquals( "#Basdl fkajsd", node.getValue().getString() );
    }


    @Test
    public void testOptionsAndEscapesFilter() throws ParseException
    {
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( null,
            "(ou;lang-de;version-124>=\\23\\42asdl fkajsd)" );
        // just check that it doesn't throw for now
        node = ( SimpleNode<?> ) node.clone();
        assertEquals( "ou;lang-de;version-124", node.getAttribute() );
        assertEquals( "#Basdl fkajsd", node.getValue().getString() );
    }


    @Test
    public void testNumericoidOptionsAndEscapesFilter() throws ParseException
    {
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( null,
            "(1.3.4.2;lang-de;version-124>=\\23\\42asdl fkajsd)" );
        // just check that it doesn't throw for now
        node = ( SimpleNode<?> ) node.clone();
        assertEquals( "1.3.4.2;lang-de;version-124", node.getAttribute() );
        assertEquals( "#Basdl fkajsd", node.getValue().getString() );
    }


    @Test
    public void testPresentFilter() throws ParseException
    {
        PresenceNode node = ( PresenceNode ) FilterParser.parse( null, "(ou=*)" );
        // just check that it doesn't throw for now
        node = ( PresenceNode ) node.clone();
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof PresenceNode );
    }


    @Test
    public void testNumericoidPresentFilter() throws ParseException
    {
        PresenceNode node = ( PresenceNode ) FilterParser.parse( null, "(1.2.3.4=*)" );
        // just check that it doesn't throw for now
        node = ( PresenceNode ) node.clone();
        assertEquals( "1.2.3.4", node.getAttribute() );
        assertTrue( node instanceof PresenceNode );
    }


    @Test
    public void testEqualsFilter() throws ParseException
    {
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( null, "(ou=people)" );
        // just check that it doesn't throw for now
        node = ( SimpleNode<?> ) node.clone();
        assertEquals( "ou", node.getAttribute() );
        assertEquals( "people", node.getValue().getString() );
        assertTrue( node instanceof EqualityNode );
    }


    @Test
    public void testEqualsWithForwardSlashFilter() throws ParseException
    {
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( null, "(ou=people/in/my/company)" );
        // just check that it doesn't throw for now
        node = ( SimpleNode<?> ) node.clone();
        assertEquals( "ou", node.getAttribute() );
        assertEquals( "people/in/my/company", node.getValue().getString() );
        assertTrue( node instanceof EqualityNode );
    }


    @Test
    public void testExtensibleFilterForm1() throws ParseException
    {
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( null,
            "(ou:dn:stupidMatch:=dummyAssertion\\23\\2A)" );
        // just check that it doesn't throw for now
        node = ( ExtensibleNode ) node.clone();
        assertEquals( "ou", node.getAttribute() );
        assertEquals( "dummyAssertion#*", node.getValue().getString() );
        assertEquals( "stupidMatch", node.getMatchingRuleId() );
        assertTrue( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm1WithNumericOid() throws ParseException
    {
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( null,
            "(1.2.3.4:dn:1.3434.23.2:=dummyAssertion\\23\\2A)" );
        // just check that it doesn't throw for now
        node = ( ExtensibleNode ) node.clone();
        assertEquals( "1.2.3.4", node.getAttribute() );
        assertEquals( "dummyAssertion#*", node.getValue().getString() );
        assertEquals( "1.3434.23.2", node.getMatchingRuleId() );
        assertTrue( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm1NoDnAttr() throws ParseException
    {
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( null, "(ou:stupidMatch:=dummyAssertion\\23\\2A)" );
        // just check that it doesn't throw for now
        node = ( ExtensibleNode ) node.clone();
        assertEquals( "ou", node.getAttribute() );
        assertEquals( "dummyAssertion#*", node.getValue().getString() );
        assertEquals( "stupidMatch", node.getMatchingRuleId() );
        assertFalse( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm1NoAttrNoMatchingRule() throws ParseException
    {
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( null, "(ou:=dummyAssertion\\23\\2A)" );
        // just check that it doesn't throw for now
        node = ( ExtensibleNode ) node.clone();
        assertEquals( "ou", node.getAttribute() );
        assertEquals( "dummyAssertion#*", node.getValue().getString() );
        assertEquals( null, node.getMatchingRuleId() );
        assertFalse( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm2() throws ParseException
    {
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( null, "(:dn:stupidMatch:=dummyAssertion\\23\\2A)" );
        // just check that it doesn't throw for now
        node = ( ExtensibleNode ) node.clone();
        assertEquals( null, node.getAttribute() );
        assertEquals( "dummyAssertion#*", node.getValue().getString() );
        assertEquals( "stupidMatch", node.getMatchingRuleId() );
        assertTrue( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm2WithNumericOid() throws ParseException
    {
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( null, "(:dn:1.3434.23.2:=dummyAssertion\\23\\2A)" );
        assertEquals( null, node.getAttribute() );
        assertEquals( "dummyAssertion#*", node.getValue().getString() );
        assertEquals( "1.3434.23.2", node.getMatchingRuleId() );
        assertTrue( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm2NoDnAttr() throws ParseException
    {
        ExtensibleNode node1 = ( ExtensibleNode ) FilterParser.parse( null, "(:stupidMatch:=dummyAssertion\\23\\2A)" );
        // just check that it doesn't throw for now
        ExtensibleNode node = ( ExtensibleNode ) node1.clone();
        assertEquals( null, node.getAttribute() );
        assertEquals( "dummyAssertion#*", node.getValue().getString() );
        assertEquals( "stupidMatch", node.getMatchingRuleId() );
        assertFalse( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm2NoDnAttrWithNumericOidNoAttr() throws ParseException
    {
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( null, "(:1.3434.23.2:=dummyAssertion\\23\\2A)" );
        // just check that it doesn't throw for now
        node = ( ExtensibleNode ) node.clone();
        assertEquals( null, node.getAttribute() );
        assertEquals( "dummyAssertion#*", node.getValue().getString() );
        assertEquals( "1.3434.23.2", node.getMatchingRuleId() );
        assertFalse( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testSubstringNoAnyNoFinal() throws ParseException
    {
        SubstringNode node = ( SubstringNode ) FilterParser.parse( null, "(ou=foo*)" );
        // just check that it doesn't throw for now
        node = ( SubstringNode ) node.clone();
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );
        assertEquals( 0, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertEquals( "foo", node.getInitial() );
        assertEquals( null, node.getFinal() );
    }


    @Test
    public void testSubstringNoAny() throws ParseException
    {
        SubstringNode node = ( SubstringNode ) FilterParser.parse( null, "(ou=foo*bar)" );
        // just check that it doesn't throw for now
        node = ( SubstringNode ) node.clone();
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );
        assertEquals( 0, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertEquals( "foo", node.getInitial() );
        assertEquals( "bar", node.getFinal() );
    }


    @Test
    public void testSubstringNoAnyNoIni() throws ParseException
    {
        SubstringNode node = ( SubstringNode ) FilterParser.parse( null, "(ou=*bar)" );
        // just check that it doesn't throw for now
        node = ( SubstringNode ) node.clone();
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );
        assertEquals( 0, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertEquals( null, node.getInitial() );
        assertEquals( "bar", node.getFinal() );
    }


    @Test
    public void testSubstringOneAny() throws ParseException
    {
        SubstringNode node = ( SubstringNode ) FilterParser.parse( null, "(ou=foo*guy*bar)" );
        // just check that it doesn't throw for now
        node = ( SubstringNode ) node.clone();
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );
        assertEquals( 1, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertTrue( node.getAny().contains( "guy" ) );
        assertEquals( "foo", node.getInitial() );
        assertEquals( "bar", node.getFinal() );
    }


    @Test
    public void testSubstringManyAny() throws ParseException
    {
        SubstringNode node = ( SubstringNode ) FilterParser.parse( null, "(ou=a*b*c*d*e*f)" );
        // just check that it doesn't throw for now
        node = ( SubstringNode ) node.clone();
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );
        assertEquals( 4, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertTrue( node.getAny().contains( "b" ) );
        assertTrue( node.getAny().contains( "c" ) );
        assertTrue( node.getAny().contains( "d" ) );
        assertTrue( node.getAny().contains( "e" ) );
        assertEquals( "a", node.getInitial() );
        assertEquals( "f", node.getFinal() );
    }


    @Test
    public void testSubstringNoIniManyAny() throws ParseException
    {
        SubstringNode node = ( SubstringNode ) FilterParser.parse( null, "(ou=*b*c*d*e*f)" );
        // just check that it doesn't throw for now
        node = ( SubstringNode ) node.clone();
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );
        assertEquals( 4, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertTrue( node.getAny().contains( "e" ) );
        assertTrue( node.getAny().contains( "b" ) );
        assertTrue( node.getAny().contains( "c" ) );
        assertTrue( node.getAny().contains( "d" ) );
        assertEquals( null, node.getInitial() );
        assertEquals( "f", node.getFinal() );
    }


    @Test
    public void testSubstringManyAnyNoFinal() throws ParseException
    {
        SubstringNode node = ( SubstringNode ) FilterParser.parse( null, "(ou=a*b*c*d*e*)" );
        // just check that it doesn't throw for now
        node = ( SubstringNode ) node.clone();
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );
        assertEquals( 4, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertTrue( node.getAny().contains( "e" ) );
        assertTrue( node.getAny().contains( "b" ) );
        assertTrue( node.getAny().contains( "c" ) );
        assertTrue( node.getAny().contains( "d" ) );
        assertEquals( "a", node.getInitial() );
        assertEquals( null, node.getFinal() );
    }


    @Test
    public void testSubstringNoIniManyAnyNoFinal() throws ParseException
    {
        SubstringNode node = ( SubstringNode ) FilterParser.parse( null, "(ou=*b*c*d*e*)" );
        // just check that it doesn't throw for now
        node = ( SubstringNode ) node.clone();

        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );
        assertEquals( 4, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertTrue( node.getAny().contains( "e" ) );
        assertTrue( node.getAny().contains( "b" ) );
        assertTrue( node.getAny().contains( "c" ) );
        assertTrue( node.getAny().contains( "d" ) );
        assertEquals( null, node.getInitial() );
        assertEquals( null, node.getFinal() );
    }


    @Test
    public void testSubstringNoAnyDoubleSpaceStar() throws ParseException
    {
        SubstringNode node = ( SubstringNode ) FilterParser.parse( null, "(ou=foo* *bar)" );
        // just check that it doesn't throw for now
        node = ( SubstringNode ) node.clone();

        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );
        assertEquals( 1, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertTrue( node.getAny().contains( " " ) );
        assertEquals( "foo", node.getInitial() );
        assertEquals( "bar", node.getFinal() );
    }


    @Test
    public void testSubstringAnyDoubleSpaceStar() throws ParseException
    {
        SubstringNode node = ( SubstringNode ) FilterParser.parse( null, "(ou=foo* a *bar)" );
        // just check that it doesn't throw for now
        node = ( SubstringNode ) node.clone();

        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );
        assertEquals( 1, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertTrue( node.getAny().contains( " a " ) );
        assertEquals( "foo", node.getInitial() );
        assertEquals( "bar", node.getFinal() );
    }


    /**
     * Enrique just found this bug with the filter parser when parsing substring
     * expressions like *any*. Here's the JIRA issue: <a
     * href="https://issues.apache.org/jira/browse/DIRSERVER-235">DIRSERVER-235</a>.
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testSubstringStarAnyStar() throws ParseException
    {
        SubstringNode node = ( SubstringNode ) FilterParser.parse( null, "(ou=*foo*)" );
        // just check that it doesn't throw for now
        node = ( SubstringNode ) node.clone();

        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );
        assertEquals( 1, node.getAny().size() );
        assertTrue( node.getAny().contains( "foo" ) );
        assertNull( node.getInitial() );
        assertNull( node.getFinal() );
    }


    @Test
    public void testEqualsFilterNullValue() throws ParseException
    {
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( null, "(ou=)" );
        // just check that it doesn't throw for now
        node = ( SimpleNode<?> ) node.clone();

        assertEquals( "ou", node.getAttribute() );
        assertEquals( "", node.getValue().getString() );
        assertTrue( node instanceof EqualityNode );
    }


    /**
     * test a filter with a # in value
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testEqualsFilterWithPoundInValue() throws ParseException
    {
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( null, "(uid=#f1)" );
        // just check that it doesn't throw for now
        node = ( SimpleNode<?> ) node.clone();
        assertEquals( "uid", node.getAttribute() );
        assertEquals( "#f1", node.getValue().getString() );
        assertTrue( node instanceof EqualityNode );
    }


    @Test
    public void testLargeBusyFilter() throws ParseException
    {
        ExprNode node1 = FilterParser
            .parse(
                null,
                "(&(|(2.5.4.3=h*)(2.5.4.4=h*)(2.16.840.1.113730.3.1.241=h*)(2.5.4.42=h*))(!(objectClass=computer))(|(objectClass=person)(objectClass=group)(objectClass=organizationalUnit)(objectClass=domain))(!(&(userAccountControl:1.2.840.113556.1.4.803:=2))))" );
        // just check that it doesn't throw for now
        ExprNode node = node1.clone();
        assertTrue( node instanceof AndNode );
        //TODO test full structure
    }
}
