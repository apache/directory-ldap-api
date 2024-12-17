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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.List;
import java.util.Locale;

import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests the FilterParserImpl class.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class FilterParserTest
{
    private boolean checkWrongFilter( String filter )
    {
        try
        {
            return FilterParser.parse( filter ) == null;
        }
        catch ( ParseException pe )
        {
            return true;
        }
    }


    /**
     * Tests to avoid deadlocks for invalid filters.
     */
    @Test
    public void testInvalidFilters()
    {
        assertTrue( checkWrongFilter( "" ) );
        assertTrue( checkWrongFilter( "   " ) );
        assertTrue( checkWrongFilter( "(" ) );
        assertTrue( checkWrongFilter( "  (" ) );
        assertTrue( checkWrongFilter( "(  " ) );
        assertTrue( checkWrongFilter( ")" ) );
        assertTrue( checkWrongFilter( "  )" ) );
        assertTrue( checkWrongFilter( "()" ) );
        assertTrue( checkWrongFilter( "(  )" ) );
        assertTrue( checkWrongFilter( "  ()  " ) );
        assertTrue( checkWrongFilter( "(cn=test(" ) );
        assertTrue( checkWrongFilter( "(cn=aaaaa" ) );
        assertTrue( checkWrongFilter( "(&(cn=abc)" ) );
    }


    @Test
    public void testItemFilter() throws ParseException
    {
        String str = "(ou~=people)";

        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertEquals( "people", node.getValue().getString() );
        assertTrue( node instanceof ApproximateNode );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testAndFilter() throws ParseException
    {
        String str = "(&(ou~=people)(age>=30))";
        BranchNode node = ( BranchNode ) FilterParser.parse( str );
        assertEquals( 2, node.getChildren().size() );
        assertTrue( node instanceof AndNode );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testAndFilterOneChildOnly() throws ParseException
    {
        String str = "(&(ou~=people))";
        BranchNode node = ( BranchNode ) FilterParser.parse( str );
        assertEquals( 1, node.getChildren().size() );
        assertTrue( node instanceof AndNode );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testOrFilter() throws ParseException
    {
        String str = "(|(ou~=people)(age>=30))";
        BranchNode node = ( BranchNode ) FilterParser.parse( str );
        assertEquals( 2, node.getChildren().size() );
        assertTrue( node instanceof OrNode );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testOrFilterOneChildOnly() throws ParseException
    {
        String str = "(|(age>=30))";
        BranchNode node = ( BranchNode ) FilterParser.parse( str );
        assertEquals( 1, node.getChildren().size() );
        assertTrue( node instanceof OrNode );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testNotFilter() throws ParseException
    {
        String str = "(!(&(ou~= people)(age>=30)))";
        BranchNode node = ( BranchNode ) FilterParser.parse( str );
        assertEquals( 1, node.getChildren().size() );
        assertTrue( node instanceof NotNode );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testOptionAndEscapesFilter() throws ParseException
    {
        String str = "(ou;lang-de>=\\23\\42asdl fkajsd)"; // \23 = '#'
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( str );
        assertEquals( "ou;lang-de", node.getAttribute() );
        assertEquals( "#Basdl fkajsd", node.getValue().getString() );
        String str2 = node.toString();
        assertEquals( "(ou;lang-de>=#Basdl fkajsd)", str2 );
    }


    @Test
    public void testOptionsAndEscapesFilter() throws ParseException
    {
        String str = "(ou;lang-de;version-124>=\\23\\42asdl fkajsd)";
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( str );
        assertEquals( "ou;lang-de;version-124", node.getAttribute() );
        assertEquals( "#Basdl fkajsd", node.getValue().getString() );
        String str2 = node.toString();
        assertEquals( "(ou;lang-de;version-124>=#Basdl fkajsd)", str2 );
    }


    @Test
    public void testNumericoidOptionsAndEscapesFilter() throws ParseException
    {
        String str = "(1.3.4.2;lang-de;version-124>=\\23\\42afdl fkajsd)";
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( str );
        assertEquals( "1.3.4.2;lang-de;version-124", node.getAttribute() );
        assertEquals( "#Bafdl fkajsd", node.getValue().getString() );
        String str2 = node.toString();
        assertEquals( "(1.3.4.2;lang-de;version-124>=#Bafdl fkajsd)", str2 );
    }


    @Test
    public void testPresentFilter() throws ParseException
    {
        String str = "(ou=*)";
        PresenceNode node = ( PresenceNode ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof PresenceNode );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testNumericoidPresentFilter() throws ParseException
    {
        String str = "(1.2.3.4=*)";
        PresenceNode node = ( PresenceNode ) FilterParser.parse( str );
        assertEquals( "1.2.3.4", node.getAttribute() );
        assertTrue( node instanceof PresenceNode );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testEqualsFilter() throws ParseException
    {
        String str = "(ou=people)";
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertEquals( "people", node.getEscapedValue() );
        assertTrue( node instanceof EqualityNode );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testBadEqualsFilter()
    {
        try
        {
            FilterParser.parse( "ou=people" );

            // The parsing should fail
            fail( "should fail with bad filter" );
        }
        catch ( ParseException pe )
        {
            assertTrue( true );
        }
    }


    @Test
    public void testEqualsWithForwardSlashFilter() throws ParseException
    {
        String str = "(ou=people/in/my/company)";
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertEquals( "people/in/my/company", node.getValue().getString() );
        assertTrue( node instanceof EqualityNode );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testExtensibleFilterForm1() throws ParseException
    {
        String str = "(ou:dn:stupidMatch:=dummyAssertion\\23\\c4\\8d)";
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertEquals( "dummyAssertion#\u010D", node.getValue().getString() );
        assertEquals( "stupidMatch", node.getMatchingRuleId() );
        assertTrue( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm1WithNumericOid() throws ParseException
    {
        String str = "(1.2.3.4:dn:1.3434.23.2:=dummyAssertion\\23\\c4\\8d)";
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( str );
        assertEquals( "1.2.3.4", node.getAttribute() );
        assertEquals( "dummyAssertion#\u010D", node.getValue().getString() );
        assertEquals( "1.3434.23.2", node.getMatchingRuleId() );
        assertTrue( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm1NoDnAttr() throws ParseException
    {
        String str = "(ou:stupidMatch:=dummyAssertion\\23\\c4\\8d)";
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertEquals( "dummyAssertion#\u010D", node.getValue().getString() );
        assertEquals( "stupidMatch", node.getMatchingRuleId() );
        assertFalse( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm1OptionOnRule()
    {
        try
        {
            FilterParser.parse( "(ou:stupidMatch;lang-de:=dummyAssertion\\23\\c4\\8d)" );
            fail( "we should never get here" );
        }
        catch ( ParseException e )
        {
            assertTrue( true );
        }
    }


    @Test
    public void testExtensibleFilterForm1NoAttrNoMatchingRule() throws ParseException
    {
        String str = "(ou:=dummyAssertion\\23\\c4\\8d)";
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertEquals( "dummyAssertion#\u010D", node.getValue().getString() );
        assertEquals( null, node.getMatchingRuleId() );
        assertFalse( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm2() throws ParseException
    {
        String str = "(:dn:stupidMatch:=dummyAssertion\\23\\c4\\8d)";
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( str );
        assertEquals( null, node.getAttribute() );
        assertEquals( "dummyAssertion#\u010D", node.getValue().getString() );
        assertEquals( "stupidMatch", node.getMatchingRuleId() );
        assertTrue( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm2OptionOnRule()
    {
        try
        {
            FilterParser.parse( "(:dn:stupidMatch;lang-en:=dummyAssertion\\23\\c4\\8d)" );
            fail( "we should never get here" );
        }
        catch ( ParseException e )
        {
            assertTrue( true );
        }
    }


    @Test
    public void testExtensibleFilterForm2WithNumericOid() throws ParseException
    {
        String str = "(:dn:1.3434.23.2:=dummyAssertion\\23\\c4\\8d)";
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( str );
        assertEquals( null, node.getAttribute() );
        assertEquals( "dummyAssertion#\u010D", node.getValue().getString() );
        assertEquals( "1.3434.23.2", node.getMatchingRuleId() );
        assertTrue( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm2NoDnAttr() throws ParseException
    {
        String str = "(:stupidMatch:=dummyAssertion\\23\\c4\\8d)";
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( str );
        assertEquals( null, node.getAttribute() );
        assertEquals( "dummyAssertion#\u010D", node.getValue().getString() );
        assertEquals( "stupidMatch", node.getMatchingRuleId() );
        assertFalse( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm2NoDnAttrWithNumericOidNoAttr() throws ParseException
    {
        String str = "(:1.3434.23.2:=dummyAssertion\\23\\c4\\8d)";
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( str );
        assertEquals( null, node.getAttribute() );
        assertEquals( "dummyAssertion#\u010D", node.getValue().getString() );
        assertEquals( "1.3434.23.2", node.getMatchingRuleId() );
        assertFalse( node.hasDnAttributes() );
        assertTrue( node instanceof ExtensibleNode );
    }


    @Test
    public void testExtensibleFilterForm3() throws ParseException
    {
        try
        {
            FilterParser.parse( "(:=dummyAssertion)" );
            fail( "Should never reach this point" );
        }
        catch ( ParseException pe )
        {
            assertTrue( true );
        }
    }


    /**
     * Test for DIRSTUDIO-1078/DIRAPI-365: unable to use # pound hash sign in LDAP filters
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testEqualsFilterForDnWithLeadingHash() throws ParseException
    {
        String str = "(memberOf=CN=\\5c#SOME,OU=Groups,OU=EMEA,DC=example,DC=net)";
        EqualityNode<?> node = ( EqualityNode<?> ) FilterParser.parse( str, true );
        assertEquals( "memberOf", node.getAttribute() );
        assertEquals( "CN=\\#SOME,OU=Groups,OU=EMEA,DC=example,DC=net", node.getValue().getString() );
    }


    /**
     * Test for DIRSTUDIO-1078/DIRAPI-365: unable to use # pound hash sign in LDAP filters
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testEqualsFilterForDnWithLeadingHashHex() throws ParseException
    {
        String str = "(memberOf=CN=\\5C23SOME,OU=Groups,OU=EMEA,DC=example,DC=net)";
        EqualityNode<?> node = ( EqualityNode<?> ) FilterParser.parse( str, true );
        assertEquals( "memberOf", node.getAttribute() );
        assertEquals( "CN=\\23SOME,OU=Groups,OU=EMEA,DC=example,DC=net", node.getValue().getString() );
    }


    /**
     * Test for DIRSTUDIO-1078/DIRAPI-365: unable to use # pound hash sign in LDAP filters
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testExtensibleFilterForDnWithLeadingHash() throws ParseException
    {
        String str = "(memberOf:1.2.840.113556.1.4.1941:=CN=\\5c#SOME,OU=Groups,OU=EMEA,DC=example,DC=net)";
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( str, true );
        assertEquals( "memberOf", node.getAttribute() );
        assertEquals( "CN=\\#SOME,OU=Groups,OU=EMEA,DC=example,DC=net", node.getValue().getString() );
        assertEquals( "1.2.840.113556.1.4.1941", node.getMatchingRuleId() );
        assertFalse( node.hasDnAttributes() );
    }


    /**
     * Test for DIRSTUDIO-1078/DIRAPI-365: unable to use # pound hash sign in LDAP filters
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testExtensibleFilterForDnWithLeadingHashHex() throws ParseException
    {
        String str = "(memberOf:1.2.840.113556.1.4.1941:=CN=\\5C23SOME,OU=Groups,OU=EMEA,DC=example,DC=net)";
        ExtensibleNode node = ( ExtensibleNode ) FilterParser.parse( str, true );
        assertEquals( "memberOf", node.getAttribute() );
        assertEquals( "CN=\\23SOME,OU=Groups,OU=EMEA,DC=example,DC=net", node.getValue().getString() );
        assertEquals( "1.2.840.113556.1.4.1941", node.getMatchingRuleId() );
        assertFalse( node.hasDnAttributes() );
    }


    @Test
    public void testReuseParser() throws ParseException
    {
        FilterParser.parse( "(ou~=people)" );
        FilterParser.parse( "(&(ou~=people)(age>=30)) " );
        FilterParser.parse( "(|(ou~=people)(age>=30)) " );
        FilterParser.parse( "(!(&(ou~=people)(age>=30)))" );
        FilterParser.parse( "(ou;lang-de>=\\23\\42asdl fkajsd)" );
        FilterParser.parse( "(ou;lang-de;version-124>=\\23\\42asdl fkajsd)" );
        FilterParser.parse( "(1.3.4.2;lang-de;version-124>=\\23\\42asdl fkajsd)" );
        FilterParser.parse( "(ou=*)" );
        FilterParser.parse( "(1.2.3.4=*)" );
        FilterParser.parse( "(ou=people)" );
        FilterParser.parse( "(ou=people/in/my/company)" );
        FilterParser.parse( "(ou:dn:stupidMatch:=dummyAssertion\\23\\c4\\8d)" );
        FilterParser.parse( "(1.2.3.4:dn:1.3434.23.2:=dummyAssertion\\23\\c4\\8d)" );
        FilterParser.parse( "(ou:stupidMatch:=dummyAssertion\\23\\c4\\8d)" );
        FilterParser.parse( "(ou:=dummyAssertion\\23\\c4\\8d)" );
        FilterParser.parse( "(1.2.3.4:1.3434.23.2:=dummyAssertion\\23\\c4\\8d)" );
        FilterParser.parse( "(:dn:stupidMatch:=dummyAssertion\\23\\c4\\8d)" );
        FilterParser.parse( "(:dn:1.3434.23.2:=dummyAssertion\\23\\c4\\8d)" );
        FilterParser.parse( "(:stupidMatch:=dummyAssertion\\23\\c4\\8d)" );
        FilterParser.parse( "(:1.3434.23.2:=dummyAssertion\\23\\c4\\8d)" );
    }


    @Test
    public void testReuseParserAfterFailures() throws ParseException
    {
        FilterParser.parse( "(ou~=people)" );
        FilterParser.parse( "(&(ou~=people)(age>=30)) " );
        FilterParser.parse( "(|(ou~=people)(age>=30)) " );
        FilterParser.parse( "(!(&(ou~=people)(age>=30)))" );
        FilterParser.parse( "(ou;lang-de>=\\23\\42asdl fkajsd)" );
        FilterParser.parse( "(ou;lang-de;version-124>=\\23\\42asdl fkajsd)" );
        FilterParser.parse( "(1.3.4.2;lang-de;version-124>=\\23\\42asdl fkajsd)" );

        try
        {
            FilterParser.parse( "(ou:stupidMatch;lang-de:=dummyAssertion\\23\\ac)" );
            fail( "we should never get here" );
        }
        catch ( ParseException e )
        {
            assertTrue( true );
        }

        FilterParser.parse( "(ou=*)" );
        FilterParser.parse( "(1.2.3.4=*)" );
        FilterParser.parse( "(ou=people)" );
        FilterParser.parse( "(ou=people/in/my/company)" );
        FilterParser.parse( "(ou:dn:stupidMatch:=dummyAssertion\\23\\ac)" );
        FilterParser.parse( "(1.2.3.4:dn:1.3434.23.2:=dummyAssertion\\23\\ac)" );
        FilterParser.parse( "(ou:stupidMatch:=dummyAssertion\\23\\ac)" );

        try
        {
            FilterParser.parse( "(:dn:stupidMatch;lang-en:=dummyAssertion\\23\\ac)" );
            fail( "we should never get here" );
        }
        catch ( ParseException e )
        {
            assertTrue( true );
        }

        FilterParser.parse( "(ou:=dummyAssertion\\23\\ac)" );
        FilterParser.parse( "(1.2.3.4:1.3434.23.2:=dummyAssertion\\23\\ac)" );
        FilterParser.parse( "(:dn:stupidMatch:=dummyAssertion\\23\\ac)" );
        FilterParser.parse( "(:dn:1.3434.23.2:=dummyAssertion\\23\\ac)" );
        FilterParser.parse( "(:stupidMatch:=dummyAssertion\\23\\ac)" );
        FilterParser.parse( "(:1.3434.23.2:=dummyAssertion\\23\\ac)" );
    }


    @Test
    public void testNullOrEmptyString() throws ParseException
    {
        try
        {
            FilterParser.parse( (String)null );
            fail( "Should not reach this point " );
        }
        catch ( ParseException pe )
        {
            assertTrue( true );
        }

        try
        {
            FilterParser.parse( "" );
            fail( "Should not reach this point " );
        }
        catch ( ParseException pe )
        {
            assertTrue( true );
        }
    }


    @Test
    public void testSubstringNoAnyNoFinal() throws ParseException
    {
        String str = "(ou=foo*)";
        SubstringNode node = ( SubstringNode ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );

        assertEquals( 0, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertEquals( "foo", node.getInitial() );
        assertEquals( null, node.getFinal() );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testSubstringNoAny() throws ParseException
    {
        String str = "(ou=foo*bar)";
        SubstringNode node = ( SubstringNode ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );

        assertEquals( 0, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertEquals( "foo", node.getInitial() );
        assertEquals( "bar", node.getFinal() );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testSubstringNoAnyNoIni() throws ParseException
    {
        String str = "(ou=*bar)";
        SubstringNode node = ( SubstringNode ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );

        assertEquals( 0, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertEquals( null, node.getInitial() );
        assertEquals( "bar", node.getFinal() );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testSubstringOneAny() throws ParseException
    {
        String str = "(ou=foo*guy*bar)";
        SubstringNode node = ( SubstringNode ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );

        assertEquals( 1, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertTrue( node.getAny().contains( "guy" ) );
        assertEquals( "foo", node.getInitial() );
        assertEquals( "bar", node.getFinal() );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testSubstringManyAny() throws ParseException
    {
        String str = "(ou=a*b*c*d*e*f)";
        SubstringNode node = ( SubstringNode ) FilterParser.parse( str );
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
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testSubstringNoIniManyAny() throws ParseException
    {
        String str = "(ou=*b*c*d*e*f)";
        SubstringNode node = ( SubstringNode ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );

        assertEquals( 4, node.getAny().size() );
        assertFalse( node.getAny().contains( new Value( "" ).getString() ) );
        assertTrue( node.getAny().contains( "e" ) );
        assertTrue( node.getAny().contains( "b" ) );
        assertTrue( node.getAny().contains( "c" ) );
        assertTrue( node.getAny().contains( "d" ) );
        assertEquals( null, node.getInitial() );
        assertEquals( "f", node.getFinal() );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testSubstringManyAnyNoFinal() throws ParseException
    {
        String str = "(ou=a*b*c*d*e*)";
        SubstringNode node = ( SubstringNode ) FilterParser.parse( str );
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
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testSubstringNoIniManyAnyNoFinal() throws ParseException
    {
        String str = "(ou=*b*c*d*e*)";
        SubstringNode node = ( SubstringNode ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );

        assertEquals( 4, node.getAny().size() );
        assertFalse( node.getAny().contains( new Value( "" ).getString() ) );
        assertTrue( node.getAny().contains( "e" ) );
        assertTrue( node.getAny().contains( "b" ) );
        assertTrue( node.getAny().contains( "c" ) );
        assertTrue( node.getAny().contains( "d" ) );
        assertEquals( null, node.getInitial() );
        assertEquals( null, node.getFinal() );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testSubstringNoAnyDoubleSpaceStar() throws ParseException
    {
        String str = "(ou=foo* *bar)";
        SubstringNode node = ( SubstringNode ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );

        assertEquals( 1, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertTrue( node.getAny().contains( " " ) );
        assertEquals( "foo", node.getInitial() );
        assertEquals( "bar", node.getFinal() );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testSubstringAnyDoubleSpaceStar() throws ParseException
    {
        String str = "(ou=foo* a *bar)";
        SubstringNode node = ( SubstringNode ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );

        assertEquals( 1, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertTrue( node.getAny().contains( " a " ) );
        assertEquals( "foo", node.getInitial() );
        assertEquals( "bar", node.getFinal() );
        String str2 = node.toString();
        assertEquals( str, str2 );
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
        String str = "(ou=*foo*)";
        SubstringNode node = ( SubstringNode ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );

        assertEquals( 1, node.getAny().size() );
        assertTrue( node.getAny().contains( "foo" ) );
        assertNull( node.getInitial() );
        assertNull( node.getFinal() );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testTwoByteUTF8Raw() throws ParseException
    {
        byte[] bytes =
            { ( byte ) 0xC2, ( byte ) 0xA2 }; // unicode U+00A2: cents sign

        new String( bytes, StandardCharsets.UTF_8 );
        String str = "(cn=\\C2\\A2)";
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( str );

        assertEquals( "cn", node.getAttribute() );
        String val = node.getValue().getString();
        assertEquals( "a2", Integer.toHexString( val.charAt( 0 ) ) ); // char is U+00A2
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testTwoByteUTF8Escaped() throws ParseException
    {
        byte[] bytes =
            { ( byte ) 0xC2, ( byte ) 0xA2 }; // unicode U+00A2: cents sign

        String str = "(cn=\\C2\\A2)";
        new String( bytes, StandardCharsets.UTF_8 );

        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( str );

        assertEquals( "cn", node.getAttribute() );
        String val = node.getValue().getString();
        assertEquals( "a2", Integer.toHexString( val.charAt( 0 ) ) ); // char is U+00A2
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testThreeByteUTF8Raw() throws ParseException
    {
        byte[] bytes =
            { ( byte ) 0xE2, ( byte ) 0x89, ( byte ) 0xA0 }; // unicode U+2260: "not equal to" sign in decimal signed bytes is -30, -119, -96

        new String( bytes, StandardCharsets.UTF_8 );
        String str = "(cn=\\E2\\89\\A0)";
        SimpleNode<?> node = (SimpleNode<?> ) FilterParser.parse( str );

        assertEquals( "cn", node.getAttribute() );
        String val = node.getValue().getString();
        assertEquals( "2260", Integer.toHexString( val.charAt( 0 ) ) );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testThreeByteUTF8Escaped() throws ParseException
    {
        byte[] bytes =
            { ( byte ) 0xE2, ( byte ) 0x89, ( byte ) 0xA0 }; // unicode U+2260: "not equal to" sign in decimal signed bytes is -30, -119, -96

        String str = "(cn=\\E2\\89\\A0aa)";
        String strEscaped = "(cn=\\E2\\89\\A0\\61\\61)";
        new String( bytes, StandardCharsets.UTF_8 );

        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( str );

        assertEquals( "cn", node.getAttribute() );
        String val = node.getValue().getString();
        assertEquals( "2260", Integer.toHexString( val.charAt( 0 ) ) );
        String str2 = node.toString();
        assertEquals( strEscaped, str2 );
    }


    @Test
    public void testThreeByteJapaneseUTF8Raw() throws ParseException
    {
        byte[] bytes =
            { ( byte ) 0xE3, ( byte ) 0x81, ( byte ) 0x99 }; // unicode U+3059: Japanese 'T' with squiggle on down-stroke.

        new String( bytes, StandardCharsets.UTF_8 );
        String str = "(cn=\\E3\\81\\99)";
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( str );

        assertEquals( "cn", node.getAttribute() );
        String val = node.getValue().getString();
        assertEquals( "3059", Integer.toHexString( val.charAt( 0 ) ) );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testThreeByteJapaneseUTF8Escaped() throws ParseException
    {
        byte[] bytes =
            { ( byte ) 0xE3, ( byte ) 0x81, ( byte ) 0x99 }; // unicode U+3059: Japanese 'T' with squiggle on down-stroke.

        String str = "(cn=\\E3\\81\\99)";
        new String( bytes, StandardCharsets.UTF_8 );

        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( str );
        assertEquals( "cn", node.getAttribute() );
        String val = node.getValue().getString();
        assertEquals( "3059", Integer.toHexString( val.charAt( 0 ) ) );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    /**
     * test a filter with a # in value
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testEqualsFilterWithPoundInValue() throws ParseException
    {
        String str = "(uid=#f1)";
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( str );
        assertEquals( "uid", node.getAttribute() );
        assertEquals( "#f1", node.getValue().getString() );
        assertTrue( node instanceof EqualityNode );
        assertEquals( str, node.toString() );
    }


    /**
     * Test that special and non allowed chars into an assertionValue are not
     * accepted. ((cf DIRSERVER-1196)
     */
    @Test
    public void testSpecialCharsInMemberOf()
    {
        try
        {
            FilterParser
                .parse( "(memberOf=1.2.840.113556.1.4.1301=$#@&*()==,2.5.4.11=local,2.5.4.11=users,2.5.4.11=readimanager)" );
            fail();
        }
        catch ( ParseException pe )
        {
            assertTrue( true );
        }
    }


    /**
     * Test that filters like (&amp;(a=b)(|(c=d)(e=f))) are correctly parsed
     */
    @Test
    public void testAndEqOr_EqEq()
    {
        try
        {
            BranchNode node = ( BranchNode ) FilterParser
                .parse( "(&(objectClass=nisNetgroup)(|(nisNetGroupTriple=a*a)(nisNetGroupTriple=\\28*,acc1,*\\29)))" );
            assertEquals( 2, node.getChildren().size() );

            assertTrue( node instanceof AndNode );

            // Check the (a=b) part
            ExprNode aEqb = node.getFirstChild();
            assertTrue( aEqb instanceof EqualityNode );
            assertEquals( "objectClass", ( ( EqualityNode<?> ) aEqb ).getAttribute() );
            assertEquals( "nisNetgroup", ( ( EqualityNode<?> ) aEqb ).getValue().getString() );

            // Check the or node
            ExprNode orNode = node.getChildren().get( 1 );
            assertTrue( orNode instanceof OrNode );

            assertEquals( 2, ( ( OrNode ) orNode ).getChildren().size() );

            ExprNode leftNode = ( ( OrNode ) orNode ).getChildren().get( 0 );

            assertTrue( leftNode instanceof SubstringNode );
            assertEquals( "nisNetGroupTriple", ( ( SubstringNode ) leftNode ).getAttribute() );
            assertEquals( "a", ( ( SubstringNode ) leftNode ).getInitial() );
            assertEquals( 0, ( ( SubstringNode ) leftNode ).getAny().size() );
            assertEquals( "a", ( ( SubstringNode ) leftNode ).getFinal() );

            ExprNode rightNode = ( ( OrNode ) orNode ).getChildren().get( 1 );

            assertTrue( rightNode instanceof SubstringNode );
            assertEquals( "nisNetGroupTriple", ( ( SubstringNode ) rightNode ).getAttribute() );
            assertEquals( "(", ( ( SubstringNode ) rightNode ).getInitial() );
            assertEquals( 1, ( ( SubstringNode ) rightNode ).getAny().size() );
            assertEquals( ",acc1,", ( ( SubstringNode ) rightNode ).getAny().get( 0 ) );
            assertEquals( ")", ( ( SubstringNode ) rightNode ).getFinal() );
        }
        catch ( ParseException pe )
        {
            assertTrue( true );
        }
    }


    @Test
    public void testObjectClassAndFilterWithSpaces() throws ParseException
    {
        String str = "(&(objectClass=person)(objectClass=organizationalUnit))";
        BranchNode node = ( BranchNode ) FilterParser.parse( str );
        assertEquals( 2, node.getChildren().size() );
        assertTrue( node instanceof AndNode );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testQuotedChars() throws ParseException
    {
        String str = "(cn='~%\\28'$'\\5C)"; // note \28='(' and \5c='\'
        ExprNode node = FilterParser.parse( str );
        assertTrue( node instanceof EqualityNode );
        assertEquals( "'~%('$'\\", ( ( EqualityNode<?> ) node ).getValue().getString() );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testQuotedCharsCase() throws ParseException
    {
        String str = "(cn='~%\\28'$'\\5Cac)"; // note \28='(' and \5c='\'
        ExprNode node = FilterParser.parse( str );
        assertTrue( node instanceof EqualityNode );
        assertEquals( "'~%('$'\\ac", ( ( EqualityNode<?> ) node ).getValue().getString() );
        String str2 = node.toString();
        assertEquals( Strings.upperCase( str ), Strings.upperCase( str2 ) );
    }


    @Test
    public void testQuotedSubstringManyAny() throws ParseException
    {
        String str = "(ou=\\5C*\\00*\\3D*\\2Abb)";
        SubstringNode node = ( SubstringNode ) FilterParser.parse( str );
        assertEquals( "ou", node.getAttribute() );
        assertTrue( node instanceof SubstringNode );

        assertEquals( 2, node.getAny().size() );
        assertFalse( node.getAny().contains( "" ) );
        assertEquals( "\\", node.getInitial() );
        assertTrue( node.getAny().contains( "\0" ) );
        assertTrue( node.getAny().contains( "=" ) );
        assertEquals( "*bb", node.getFinal() );
        String str2 = node.toString();
        assertEquals( "(ou=\\5C*\\00*=*\\2Abb)", str2 );
    }


    /*
    @Test
    public void testPerf() throws ParseException
    {
        String filter = "(&(ou=abcdefg)(!(ou=hijkl))(&(a=bcd)(ew=fgh)))";
        FilterParser parser = new FilterParserImpl();
        
        long t0 = System.currentTimeMillis();
        
        for ( int i = 0; i < 1000000; i++ )
        {
            parser.parse( filter );
        }
        
        long t1 = System.currentTimeMillis();
        
        System.out.println( " Delta = " + (t1 - t0) );

        long t2 = System.currentTimeMillis();
        
        for ( int i = 0; i < 10000000; i++ )
        {
            FastFilterParserImpl.parse( filter );
        }
        
        long t3 = System.currentTimeMillis();
        
        System.out.println( " Delta = " + (t3 - t2) );
    }
    */

    @Test
    public void testBinaryValueEscaped() throws ParseException
    {
        String str = "(objectguid=\\29\\4C\\04\\B5\\D4\\ED\\38\\46\\87\\EE\\77\\58\\5C\\32\\AD\\91)";
        FilterParser.parse( str );
    }


    @Test
    public void testAndFilterFollowed() throws ParseException
    {
        String str = "(&(ou~=people)(age>=30))} some more text";
        BranchNode node = ( BranchNode ) FilterParser.parse( str );
        assertEquals( 2, node.getChildren().size() );
        assertTrue( node instanceof AndNode );
        String str2 = node.toString();
        assertTrue( str.startsWith( str2 ) );
        assertEquals( "(&(ou~=people)(age>=30))", str2 );
    }


    @Test
    public void testFilterOrder() throws ParseException
    {
        String filterStr1 = "(&(&(jagplayUserGroup=Active)(!(jagplayUserGroup=Banned))(jagplayUserNickname=admin)))";
        String filterStr2 = "(&(jagplayUserNickname=admin)(&(jagplayUserGroup=Active)(!(jagplayUserGroup=Banned)))) ";

        BranchNode node1 = ( BranchNode ) FilterParser.parse( filterStr1 );
        BranchNode node2 = ( BranchNode ) FilterParser.parse( filterStr2 );

        // Check Node 1
        assertEquals( 1, node1.getChildren().size() );

        assertTrue( node1 instanceof AndNode );
        ExprNode andNode1 = node1.getChildren().get( 0 );
        assertTrue( andNode1 instanceof AndNode );
        List<ExprNode> children1 = ( ( AndNode ) andNode1 ).getChildren();
        assertEquals( 3, children1.size() );

        // First child : (jagplayUserGroup=Active)
        ExprNode child1 = children1.get( 0 );
        assertTrue( child1 instanceof EqualityNode );
        assertEquals( "jagplayUserGroup", ( ( EqualityNode<?> ) child1 ).getAttribute() );
        assertEquals( "Active", ( ( EqualityNode<?> ) child1 ).getValue().getString() );

        // Second child : (!(jagplayUserGroup=Banned))
        ExprNode child2 = children1.get( 1 );
        assertTrue( child2 instanceof NotNode );
        NotNode notNode1 = ( NotNode ) child2;

        ExprNode notNodeChild1 = notNode1.getFirstChild();
        assertTrue( notNodeChild1 instanceof EqualityNode );
        assertEquals( "jagplayUserGroup", ( ( EqualityNode<?> ) notNodeChild1 ).getAttribute() );
        assertEquals( "Banned", ( ( EqualityNode<?> ) notNodeChild1 ).getValue().getString() );

        // Third child : (jagplayUserNickname=admin)
        ExprNode child3 = children1.get( 2 );
        assertTrue( child3 instanceof EqualityNode );
        assertEquals( "jagplayUserNickname", ( ( EqualityNode<?> ) child3 ).getAttribute() );
        assertEquals( "admin", ( ( EqualityNode<?> ) child3 ).getValue().getString() );

        // Check Node 2 : (&(jagplayUserNickname=admin)(&(jagplayUserGroup=Active)(!(jagplayUserGroup=Banned))))
        assertEquals( 2, node2.getChildren().size() );
        assertTrue( node2 instanceof AndNode );

        child1 = node2.getChildren().get( 0 );
        assertTrue( child1 instanceof EqualityNode );
        assertEquals( "jagplayUserNickname", ( ( EqualityNode<?> ) child1 ).getAttribute() );
        assertEquals( "admin", ( ( EqualityNode<?> ) child1 ).getValue().getString() );

        child2 = node2.getChildren().get( 1 );
        assertTrue( child2 instanceof AndNode );
        AndNode andNode2 = ( ( AndNode ) child2 );
        assertEquals( 2, andNode2.getChildren().size() );

        // First child : (jagplayUserGroup=Active)
        child1 = andNode2.getChildren().get( 0 );
        assertTrue( child1 instanceof EqualityNode );
        assertEquals( "jagplayUserGroup", ( ( EqualityNode<?> ) child1 ).getAttribute() );
        assertEquals( "Active", ( ( EqualityNode<?> ) child1 ).getValue().getString() );

        // second child : (!(jagplayUserGroup=Banned))
        child2 = andNode2.getChildren().get( 1 );
        assertTrue( child2 instanceof NotNode );
        notNode1 = ( NotNode ) child2;

        notNodeChild1 = notNode1.getFirstChild();
        assertTrue( notNodeChild1 instanceof EqualityNode );
        assertEquals( "jagplayUserGroup", ( ( EqualityNode<?> ) notNodeChild1 ).getAttribute() );
        assertEquals( "Banned", ( ( EqualityNode<?> ) notNodeChild1 ).getValue().getString() );
    }


    @Test
    public void testEqualsFilterWithUnderscoreRelaxed() throws ParseException
    {
        String str = "(a_b_=people)";
        SimpleNode<?> node = ( SimpleNode<?> ) FilterParser.parse( str, true );
        assertEquals( "a_b_", node.getAttribute() );
        assertEquals( "people", node.getValue().getString() );
        assertTrue( node instanceof EqualityNode );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testEqualsFilterWithUnderscoreNotRelaxed() throws ParseException
    {
        String str = "(a_b_=people)";
        
        assertThrows( ParseException.class, () -> 
        {
            FilterParser.parse( str, false );
        } );
    }


    @Test
    public void testAndFilterWithUnderscoreRelaxed() throws ParseException
    {
        String str = "(&(o_u~=people)(a_g_e>=30))";
        BranchNode node = ( BranchNode ) FilterParser.parse( str, true );
        assertEquals( 2, node.getChildren().size() );
        assertTrue( node instanceof AndNode );
        String str2 = node.toString();
        assertEquals( str, str2 );
    }


    @Test
    public void testAndFilterWithUnderscoreNotRelaxed() throws ParseException
    {
        String str = "(&(o_u~=people)(a_g_e>=30))";
        
        assertThrows( ParseException.class, () -> 
        {
            FilterParser.parse( str, false );
        } );
    }


    @Test
    public void testRelaxedFilterParse() throws ParseException
    {
        String str = " ( cn =*) ";
        ExprNode node = FilterParser.parse( str, false );
        
        assertTrue( node instanceof PresenceNode );
        assertEquals( "cn", ((PresenceNode)node).attribute );
        
        str = " ( & ( cn =*) ) ";
        node = FilterParser.parse( str, false );

        assertTrue( node instanceof AndNode );
        assertEquals( 1, ((AndNode)node).children.size() );
        
        ExprNode child = ((AndNode)node).children.get( 0 );
        assertTrue( child instanceof PresenceNode );
        assertEquals( "cn", ((PresenceNode)child).attribute );
    }
    
    
    @Test
    public void testFilterWithSpecialChars() throws ParseException
    {
        String filterStr = String.format( Locale.ROOT, "(%s=%s)", "cn", FilterEncoder.encodeFilterValue( "ACME(tm)" ) );
        
        assertEquals( "(cn=ACME\\28tm\\29)", filterStr );
        
        String filterStr2 = new EqualityNode<>( "cn", "ACME(tm)" ).toString();
        
        assertEquals( "(cn=ACME\\28tm\\29)", filterStr2 );
    }
}
