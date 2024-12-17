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
package org.apache.directory.api.ldap.model.ldif;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.directory.api.ldap.model.entry.*;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests the LdifReverter methods
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class LdifRevertorTest
{
    /**
     * Helper method to build a basic entry used by the Modify tests
     */
    private Entry buildEntry() throws LdapException
    {
        Entry entry = new DefaultEntry( "",
            "objectclass: top",
            "objectclass: person",
            "cn: test",
            "sn: joe doe",
            "l: USA" );

        return entry;
    }


    /**
     * Test a AddRequest reverse
     *
     * @throws LdapInvalidDnException If the test failed
     */
    @Test
    public void testReverseAdd() throws LdapInvalidDnException
    {
        Dn dn = new Dn( "dc=apache, dc=com" );
        LdifEntry reversed = LdifRevertor.reverseAdd( dn );

        assertNotNull( reversed );
        assertEquals( dn.getName(), reversed.getDn().getName() );
        assertEquals( ChangeType.Delete, reversed.getChangeType() );
        assertNull( reversed.getEntry() );
    }


    /**
     * Test a DelRequest reverse
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testReverseDel() throws LdapException
    {
        Dn dn = new Dn( "dc=apache, dc=com" );

        Entry deletedEntry = new DefaultEntry( dn ,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "sn: apache",
            "dc: apache" );

        LdifEntry reversed = LdifRevertor.reverseDel( dn, deletedEntry );

        assertNotNull( reversed );
        assertEquals( dn.getName(), reversed.getDn().getName() );
        assertEquals( ChangeType.Add, reversed.getChangeType() );
        assertNotNull( reversed.getEntry() );
        assertEquals( deletedEntry, reversed.getEntry() );
    }


    /**
     * Test a reversed Modify adding a existing value from an existing attribute
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testReverseModifyDelExistingOuValue() throws LdapException
    {
        Entry modifiedEntry = buildEntry();

        modifiedEntry.put( "ou", "apache", "acme corp" );

        Dn dn = new Dn( "cn=test, ou=system" );

        Modification mod = new DefaultModification(
            ModificationOperation.REMOVE_ATTRIBUTE,
            new DefaultAttribute( "ou", "acme corp" ) );

        LdifEntry reversed = LdifRevertor.reverseModify( dn,
            Collections.<Modification> singletonList( mod ), modifiedEntry );

        assertNotNull( reversed );
        assertEquals( dn.getName(), reversed.getDn().getName() );
        assertEquals( ChangeType.Modify, reversed.getChangeType() );
        assertNull( reversed.getEntry() );

        List<Modification> mods = reversed.getModifications();

        assertNotNull( mods );
        assertEquals( 1, mods.size() );

        Modification modif = mods.get( 0 );

        assertEquals( ModificationOperation.ADD_ATTRIBUTE, modif.getOperation() );

        Attribute attr = modif.getAttribute();

        assertNotNull( attr );

        assertEquals( "ou", attr.getId() );
        assertEquals( "acme corp", attr.getString() );
    }


    /**
     * Test a reversed Modify deleting an existing attribute
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testReverseModifyDeleteOU() throws LdapException
    {
        Entry modifiedEntry = buildEntry();

        modifiedEntry.put( "ou", "apache", "acme corp" );

        Dn dn = new Dn( "cn=test, ou=system" );

        Modification mod = new DefaultModification(
            ModificationOperation.REMOVE_ATTRIBUTE,
            new DefaultAttribute( "ou" ) );

        LdifEntry reversed = LdifRevertor.reverseModify( dn,
            Collections.<Modification> singletonList( mod ), modifiedEntry );

        assertNotNull( reversed );
        assertEquals( dn.getName(), reversed.getDn().getName() );
        assertEquals( ChangeType.Modify, reversed.getChangeType() );
        assertNull( reversed.getEntry() );

        List<Modification> mods = reversed.getModifications();

        assertNotNull( mods );
        assertEquals( 1, mods.size() );

        Modification modif = mods.get( 0 );

        assertEquals( ModificationOperation.ADD_ATTRIBUTE, modif.getOperation() );

        Attribute attr = modif.getAttribute();

        assertNotNull( attr );
        assertEquals( "ou", attr.getId() );

        assertTrue( attr.contains( "apache", "acme corp" ) );
    }


    /**
     * Test a reversed Modify deleting all values of an existing attribute
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testReverseModifyDelExistingOuWithAllValues() throws LdapException
    {
        Entry modifiedEntry = buildEntry();

        Attribute ou = new DefaultAttribute( "ou", "apache", "acme corp" );
        modifiedEntry.put( ou );

        Dn dn = new Dn( "cn=test, ou=system" );

        Modification mod = new DefaultModification(
            ModificationOperation.REMOVE_ATTRIBUTE, ou );

        LdifEntry reversed = LdifRevertor.reverseModify( dn,
            Collections.<Modification> singletonList( mod ), modifiedEntry );

        assertNotNull( reversed );
        assertEquals( dn.getName(), reversed.getDn().getName() );
        assertEquals( ChangeType.Modify, reversed.getChangeType() );
        assertNull( reversed.getEntry() );

        List<Modification> mods = reversed.getModifications();

        assertNotNull( mods );
        assertEquals( 1, mods.size() );

        Modification modif = mods.get( 0 );

        assertEquals( ModificationOperation.ADD_ATTRIBUTE, modif.getOperation() );

        Attribute attr = modif.getAttribute();

        assertNotNull( attr );
        assertEquals( "ou", attr.getId() );

        assertTrue( ou.contains( "apache", "acme corp" ) );
    }


    /**
     * Test a reversed Modify replacing existing values with new values
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testReverseModifyReplaceExistingOuValues() throws LdapException
    {
        Entry modifiedEntry = buildEntry();

        Attribute ou = new DefaultAttribute( "ou", "apache", "acme corp" );
        modifiedEntry.put( ou );

        Dn dn = new Dn( "cn=test, ou=system" );

        Attribute ouModified = new DefaultAttribute( "ou", "directory", "BigCompany inc." );

        Modification mod = new DefaultModification(
            ModificationOperation.REPLACE_ATTRIBUTE, ouModified );

        LdifEntry reversed = LdifRevertor.reverseModify( dn,
            Collections.<Modification> singletonList( mod ), modifiedEntry );

        assertNotNull( reversed );
        assertEquals( dn.getName(), reversed.getDn().getName() );
        assertEquals( ChangeType.Modify, reversed.getChangeType() );
        assertNull( reversed.getEntry() );

        List<Modification> mods = reversed.getModifications();

        assertNotNull( mods );
        assertEquals( 1, mods.size() );

        Modification modif = mods.get( 0 );

        assertEquals( ModificationOperation.REPLACE_ATTRIBUTE, modif.getOperation() );

        Attribute attr = modif.getAttribute();

        assertNotNull( attr );
        assertEquals( ou, attr );
    }


    /**
     * Test a reversed Modify replace by injecting a new attribute
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testReverseModifyReplaceNewAttribute() throws LdapException
    {
        Entry modifiedEntry = buildEntry();

        Dn dn = new Dn( "cn=test, ou=system" );

        Attribute newOu = new DefaultAttribute( "ou", "apache", "acme corp" );

        Modification mod = new DefaultModification(
            ModificationOperation.REPLACE_ATTRIBUTE, newOu );

        LdifEntry reversed = LdifRevertor.reverseModify( dn,
            Collections.<Modification> singletonList( mod ), modifiedEntry );

        assertNotNull( reversed );
        assertEquals( dn.getName(), reversed.getDn().getName() );
        assertEquals( ChangeType.Modify, reversed.getChangeType() );
        assertNull( reversed.getEntry() );

        List<Modification> mods = reversed.getModifications();

        assertNotNull( mods );
        assertEquals( 1, mods.size() );

        Modification modif = mods.get( 0 );

        assertEquals( ModificationOperation.REPLACE_ATTRIBUTE, modif.getOperation() );

        Attribute attr = modif.getAttribute();

        assertNotNull( attr );
        assertEquals( "ou", attr.getId() );

        assertNull( attr.get() );
    }


    /**
     * Test a reversed Modify replace by removing an attribute
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testReverseModifyReplaceExistingOuWithNothing() throws LdapException
    {
        Entry modifiedEntry = buildEntry();

        modifiedEntry.put( "ou", "apache", "acme corp" );

        Dn dn = new Dn( "cn=test, ou=system" );

        Modification mod = new DefaultModification(
            ModificationOperation.REPLACE_ATTRIBUTE, new DefaultAttribute( "ou" ) );

        LdifEntry reversed = LdifRevertor.reverseModify( dn,
            Collections.<Modification> singletonList( mod ), modifiedEntry );

        assertNotNull( reversed );
        assertEquals( dn.getName(), reversed.getDn().getName() );
        assertEquals( ChangeType.Modify, reversed.getChangeType() );
        assertNull( reversed.getEntry() );

        List<Modification> mods = reversed.getModifications();

        assertNotNull( mods );
        assertEquals( 1, mods.size() );

        Modification modif = mods.get( 0 );

        assertEquals( ModificationOperation.REPLACE_ATTRIBUTE, modif.getOperation() );

        Attribute attr = modif.getAttribute();

        assertNotNull( attr );
        assertEquals( "ou", attr.getId() );

        assertTrue( attr.contains( "apache", "acme corp" ) );
    }


    /**
     * Test a multiple modifications reverse.
     * 
     * On the following entry :
     *  dn: cn=test, ou=system
     *  objectclass: top
     *  objectclass: person
     *  cn: test
     *  sn: joe doe
     *  l: USA
     *  ou: apache
     *  ou: acme corp
     * 
     * We will :
     *  - add an 'ou' value 'BigCompany inc.'
     *  - delete the 'l' attribute
     *  - add the 'l=FR' attribute
     *  - replace the 'l=FR' by a 'l=USA' attribute
     *  - replace the 'ou' attribute with 'apache' value.
     * 
     * The modify ldif will be :
     * 
     *  dn: cn=test, ou=system
     *  changetype: modify
     *  add: ou
     *  ou: BigCompany inc.
     *  -
     *  delete: l
     *  -
     *  add: l
     *  l: FR
     *  -
     *  replace: l
     *  l: USA
     *  -
     *  replace: ou
     *  ou: apache
     *  -
     * 
     * At the end, the entry will looks like :
     *  dn: cn=test, ou=system
     *  objectclass: top
     *  objectclass: person
     *  cn: test
     *  sn: joe doe
     *  l: USA
     *  ou: apache
     * 
     * and the reversed LDIF will be :
     * 
     *  dn: cn=test, ou=system
     *  changetype: modify
     *  replace: ou
     *  ou: apache
     *  ou: acme corp
     *  -
     *  replace: l
     *  l: USA
     *  -
     *  delete: l
     *  l: FR
     *  -
     *  add: l
     *  l: USA
     *  -
     *  delete: ou
     *  ou: BigCompany inc.
     *  -
     * 
     * 
     * @throws Exception If the test failed
     */
    @Test
    public void testReverseMultipleModifications() throws Exception
    {
        String initialEntryLdif =
            "dn: cn=test, ou=system\n" +
                "objectclass: top\n" +
                "objectclass: person\n" +
                "cn: test\n" +
                "sn: joe doe\n" +
                "l: USA\n" +
                "ou: apache\n" +
                "ou: acme corp\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( initialEntryLdif );
        reader.close();

        LdifEntry initialEntry = entries.get( 0 );

        // We will :
        //   - add an 'ou' value 'BigCompany inc.'
        //   - delete the 'l' attribute
        //   - add the 'l=FR' attribute
        //   - replace the 'l=FR' by a 'l=USA' attribute
        //   - replace the 'ou' attribute with 'apache' value.
        Dn dn = new Dn( "cn=test, ou=system" );

        List<Modification> modifications = new ArrayList<Modification>();

        // First, inject the 'ou'
        Modification mod = new DefaultModification(
            ModificationOperation.ADD_ATTRIBUTE, new DefaultAttribute( "ou", "BigCompany inc." ) );
        modifications.add( mod );

        // Remove the 'l'
        mod = new DefaultModification(
            ModificationOperation.REMOVE_ATTRIBUTE, new DefaultAttribute( "l" ) );
        modifications.add( mod );

        // Add 'l=FR'
        mod = new DefaultModification(
            ModificationOperation.ADD_ATTRIBUTE, new DefaultAttribute( "l", "FR" ) );
        modifications.add( mod );

        // Replace it with 'l=USA'
        mod = new DefaultModification(
            ModificationOperation.REPLACE_ATTRIBUTE, new DefaultAttribute( "l", "USA" ) );
        modifications.add( mod );

        // Replace the ou value
        mod = new DefaultModification(
            ModificationOperation.REPLACE_ATTRIBUTE, new DefaultAttribute( "ou", "apache" ) );
        modifications.add( mod );

        LdifEntry reversedEntry = LdifRevertor.reverseModify( dn, modifications, initialEntry.getEntry() );

        String expectedEntryLdif =
            "dn: cn=test, ou=system\n" +
                "changetype: modify\n" +
                "replace: ou\n" +
                "ou: apache\n" +
                "ou: acme corp\n" +
                "ou: BigCompany inc.\n" +
                "-\n" +
                "replace: l\n" +
                "l: FR\n" +
                "-\n" +
                "delete: l\n" +
                "l: FR\n" +
                "-\n" +
                "add: l\n" +
                "l: USA\n" +
                "-\n" +
                "delete: ou\n" +
                "ou: BigCompany inc.\n" +
                "-\n\n";

        reader = new LdifReader();
        entries = reader.parseLdif( expectedEntryLdif );
        reader.close();

        LdifEntry expectedEntry = entries.get( 0 );

        assertEquals( expectedEntry, reversedEntry );
    }


    /**
     * Test a reversed Modify adding a new attribute value
     * in an exiting attribute
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testReverseModifyAddNewOuValue() throws LdapException
    {
        Entry modifiedEntry = buildEntry();

        modifiedEntry.put( "ou", "apache", "acme corp" );

        Dn dn = new Dn( "cn=test, ou=system" );
        Modification mod = new DefaultModification(
            ModificationOperation.ADD_ATTRIBUTE,
            new DefaultAttribute( "ou", "BigCompany inc." ) );

        LdifEntry reversed = LdifRevertor.reverseModify( dn,
            Collections.<Modification> singletonList( mod ), modifiedEntry );

        assertNotNull( reversed );
        assertEquals( dn.getName(), reversed.getDn().getName() );
        assertEquals( ChangeType.Modify, reversed.getChangeType() );
        assertNull( reversed.getEntry() );
        List<Modification> mods = reversed.getModifications();

        assertNotNull( mods );
        assertEquals( 1, mods.size() );

        Modification modif = mods.get( 0 );

        assertEquals( ModificationOperation.REMOVE_ATTRIBUTE, modif.getOperation() );

        Attribute attr = modif.getAttribute();

        assertNotNull( attr );
        assertEquals( "ou", attr.getId() );
        assertEquals( "BigCompany inc.", attr.getString() );
    }


    /**
     * Test a reversed Modify adding a new attribute
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testReverseModifyAddNewOu() throws LdapException
    {
        Entry modifiedEntry = buildEntry();

        Dn dn = new Dn( "cn=test, ou=system" );
        Modification mod = new DefaultModification(
            ModificationOperation.ADD_ATTRIBUTE,
            new DefaultAttribute( "ou", "BigCompany inc." ) );

        LdifEntry reversed = LdifRevertor.reverseModify( dn,
            Collections.<Modification> singletonList( mod ), modifiedEntry );

        assertNotNull( reversed );
        assertEquals( dn.getName(), reversed.getDn().getName() );
        assertEquals( ChangeType.Modify, reversed.getChangeType() );
        assertNull( reversed.getEntry() );
        List<Modification> mods = reversed.getModifications();

        assertNotNull( mods );
        assertEquals( 1, mods.size() );

        Modification modif = mods.get( 0 );

        assertEquals( ModificationOperation.REMOVE_ATTRIBUTE, modif.getOperation() );

        Attribute attr = modif.getAttribute();

        assertNotNull( attr );
        assertEquals( "ou", attr.getId() );
        assertEquals( "BigCompany inc.", attr.getString() );
    }


    /**
     * Test a AddRequest reverse where the Dn is to be base64 encoded
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testReverseAddBase64DN() throws LdapException
    {
        Dn dn = new Dn( "dc=Emmanuel L\u00c9charny" );
        LdifEntry reversed = LdifRevertor.reverseAdd( dn );
        assertNotNull( reversed );
        assertEquals( dn.getName(), reversed.getDn().getName() );
        assertEquals( ChangeType.Delete, reversed.getChangeType() );
        assertNull( reversed.getEntry() );
    }


    /**
     * Test a reversed move ModifyDN
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testReverseModifyDNMove() throws LdapException
    {
        Dn dn = new Dn( "cn=john doe, dc=example, dc=com" );
        Dn newSuperior = new Dn( "ou=system" );
        Rdn rdn = new Rdn( "cn=john doe" );

        LdifEntry reversed = LdifRevertor.reverseMove( newSuperior, dn );

        assertNotNull( reversed );

        assertEquals( "cn=john doe,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModDn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( rdn.getName(), reversed.getNewRdn() );
        assertEquals( "dc=example, dc=com", Strings.trim( reversed.getNewSuperior() ) );
        assertNull( reversed.getEntry() );
    }


    /**
     * Test a reversed rename ModifyDN, where the Rdn are both simple, not overlapping,
     * with deleteOldRdn = false, and the Ava not present in the initial entry?
     * 
     * Covers case 1.1 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * sn: This is a test
     * 
     * new Rdn : cn=joe
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test11ReverseRenameSimpleSimpleNotOverlappingKeepOldRdnDontExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "cn=test" );
        Rdn newRdn = new Rdn( "cn=joe" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.KEEP_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=joe,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertTrue( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the Rdn are both simple, not overlapping,
     * with deleteOldRdn = false, and with a Ava present in the initial entry.
     * 
     * Covers case 1.2 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * cn: small
     * sn: This is a test
     * 
     * new Rdn : cn=small
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test12ReverseRenameSimpleSimpleNotOverlappingKeepOldRdnExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "cn=test" );
        Rdn newRdn = new Rdn( "cn=small" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "cn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.KEEP_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=small,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the Rdn are both simple, not overlapping,
     * with deleteOldRdn = true, and the Ava not present in the initial entry
     * 
     * Covers case 2.1 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * sn: This is a test
     * 
     * new Rdn : cn=joe
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test21ReverseRenameSimpleSimpleNotOverlappingDeleteOldRdnDontExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "cn=test" );
        Rdn newRdn = new Rdn( "cn=joe" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.DELETE_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=joe,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertTrue( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the Rdn are both simple, not overlapping,
     * with deleteOldRdn = true, and with a Ava present in the initial entry.
     * 
     * Covers case 2.2 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * cn: small
     * sn: This is a test
     * 
     * new Rdn : cn=small
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test22ReverseRenameSimpleSimpleNotOverlappingDeleteOldRdnExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "cn=test" );
        Rdn newRdn = new Rdn( "cn=small" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "cn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.DELETE_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=small,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is composite,
     * the new Rdn is simple, not overlapping, with deleteOldRdn = false, and
     * with a Ava not present in the initial entry.
     * 
     * Covers case 3 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: sn=small+cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : cn=joe
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test3ReverseRenameCompositeSimpleNotOverlappingKeepOldRdnDontExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "sn=small+cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "sn=small+cn=test" );
        Rdn newRdn = new Rdn( "cn=joe" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.KEEP_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=joe,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertTrue( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is composite,
     * the new Rdn is simple, not overlapping, with deleteOldRdn = false, and
     * with an Ava present in the initial entry.
     * 
     * Covers case 3 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: sn=small+cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * cn: big
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : cn=big
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test3ReverseRenameCompositeSimpleNotOverlappingKeepOldRdnExistsInEntry() throws LdapException
    {
        Dn dn = new Dn( "sn=small+cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "sn=small+cn=test" );
        Rdn newRdn = new Rdn( "cn=big" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "cn: big",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.KEEP_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=big,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is composite,
     * the new Rdn is simple, not overlapping, with deleteOldRdn = true, and
     * with an Ava not present in the initial entry.
     * 
     * Covers case 4 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: sn=small+cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : cn=joe
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test4ReverseRenameCompositeSimpleNotOverlappingDeleteOldRdnDontExistsInEntry() throws LdapException
    {
        Dn dn = new Dn( "sn=small+cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "sn=small+cn=test" );
        Rdn newRdn = new Rdn( "cn=joe" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.DELETE_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=joe,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertTrue( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is composite,
     * the new Rdn is simple, not overlapping, with deleteOldRdn = true, and
     * with an Ava present in the initial entry.
     * 
     * Covers case 4 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: sn=small+cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * cn: big
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : cn=big
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test4ReverseRenameCompositeSimpleNotOverlappingDeleteOldRdnExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "sn=small+cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "sn=small+cn=test" );
        Rdn newRdn = new Rdn( "cn=big" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "cn: big",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.DELETE_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=big,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is composite,
     * the new Rdn is simple, they overlap, with deleteOldRdn = false.
     * 
     * Covers case 5 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: sn=small+cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : cn=test
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test5ReverseRenameCompositeSimpleOverlappingKeepOldRdn() throws LdapException
    {
        Dn dn = new Dn( "sn=small+cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "sn=small+cn=test" );
        Rdn newRdn = new Rdn( "cn=test" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.KEEP_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=test,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is composite,
     * the new Rdn is simple, they overlap, with deleteOldRdn = true.
     * 
     * Covers case 5 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: sn=small+cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : cn=test
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test5ReverseRenameCompositeSimpleOverlappingDeleteOldRdn() throws LdapException
    {
        Dn dn = new Dn( "sn=small+cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "sn=small+cn=test" );
        Rdn newRdn = new Rdn( "cn=test" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.DELETE_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=test,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is simple,
     * the new Rdn is composite, they don't overlap, with deleteOldRdn = false, and
     * the new values don't exist in the entry.
     * 
     * Covers case 6.1 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * cn: small
     * sn: This is a test
     * 
     * new Rdn : cn=joe+sn=plumber
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test61ReverseRenameSimpleCompositeNotOverlappingKeepOldRdnDontExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "cn=test" );
        Rdn newRdn = new Rdn( "cn=joe+sn=plumber" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "cn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.KEEP_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=joe+sn=plumber,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertTrue( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is simple,
     * the new Rdn is composite, they don't overlap, with deleteOldRdn = false, and
     * the new values exists in the entry.
     * 
     * Covers case 6.2 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : cn=joe+sn=small
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test62ReverseRenameSimpleCompositeNotOverlappingKeepOldRdnDontExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "cn=test" );
        Rdn newRdn = new Rdn( "cn=joe+sn=small" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.KEEP_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 2, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=joe+sn=small,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );

        reversed = reverseds.get( 1 );

        assertEquals( "cn=test,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.Modify, reversed.getChangeType() );
        Modification[] mods = reversed.getModificationArray();

        assertNotNull( mods );
        assertEquals( 1, mods.length );
        assertEquals( ModificationOperation.REMOVE_ATTRIBUTE, mods[0].getOperation() );
        assertNotNull( mods[0].getAttribute() );
        assertEquals( "cn", mods[0].getAttribute().getId() );
        assertEquals( "joe", mods[0].getAttribute().getString() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is simple,
     * the new Rdn is composite, they don't overlap, with deleteOldRdn = true, and
     * none of new values exists in the entry.
     * 
     * Covers case 7.1 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * cn: small
     * sn: This is a test
     * 
     * new Rdn : cn=joe+sn=plumber
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test71ReverseRenameSimpleCompositeNotOverlappingDeleteOldRdnDontExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "cn=test" );
        Rdn newRdn = new Rdn( "cn=joe+sn=plumber" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "cn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.DELETE_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=joe+sn=plumber,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertTrue( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is simple,
     * the new Rdn is composite, they don't overlap, with deleteOldRdn = true, and
     * some of new values exists in the entry.
     * 
     * Covers case 7.2 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : cn=joe+sn=small
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test72ReverseRenameSimpleCompositeNotOverlappingDeleteOldRdnExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "cn=test" );
        Rdn newRdn = new Rdn( "cn=joe+sn=small" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.DELETE_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 2, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=joe+sn=small,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );

        reversed = reverseds.get( 1 );

        assertEquals( "cn=test,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.Modify, reversed.getChangeType() );
        Modification[] mods = reversed.getModificationArray();

        assertNotNull( mods );
        assertEquals( 1, mods.length );
        assertEquals( ModificationOperation.REMOVE_ATTRIBUTE, mods[0].getOperation() );
        assertNotNull( mods[0].getAttribute() );
        assertEquals( "cn", mods[0].getAttribute().getId() );
        assertEquals( "joe", mods[0].getAttribute().getString() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is simple,
     * the new Rdn is composite, they overlap, with deleteOldRdn = false, and
     * none of new values exists in the entry.
     * 
     * Covers case 8.1 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * cn: big
     * sn: This is a test
     * 
     * new Rdn : sn=small+cn=test
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test81ReverseRenameSimpleCompositeOverlappingKeepOldRdnDontExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "cn=test" );
        Rdn newRdn = new Rdn( "sn=small+cn=test" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "cn: big",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.KEEP_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "sn=small+cn=test,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertTrue( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is simple,
     * the new Rdn is composite, they overlap, with deleteOldRdn = false, and
     * some of the new values exist in the entry.
     * 
     * Covers case 8.2 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * sn: This is a test
     * seeAlso: big
     * 
     * new Rdn : sn=small+cn=test+seeAlso=big
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test82ReverseRenameSimpleCompositeOverlappingKeepOldRdnExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "cn=test" );
        Rdn newRdn = new Rdn( "sn=small+cn=test+seeAlso=big" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "seeAlso: big",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.KEEP_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 2, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "sn=small+cn=test+seeAlso=big,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );

        reversed = reverseds.get( 1 );

        assertEquals( "cn=test,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.Modify, reversed.getChangeType() );
        Modification[] mods = reversed.getModificationArray();

        assertNotNull( mods );
        assertEquals( 1, mods.length );
        assertEquals( ModificationOperation.REMOVE_ATTRIBUTE, mods[0].getOperation() );
        assertNotNull( mods[0].getAttribute() );
        assertEquals( "sn", mods[0].getAttribute().getId() );
        assertEquals( "small", mods[0].getAttribute().getString() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is simple,
     * the new Rdn is composite, they overlap, with deleteOldRdn = true, and
     * none of new values exists in the entry.
     * 
     * Covers case 9.1 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * cn: big
     * sn: This is a test
     * 
     * new Rdn : sn=small+cn=test
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test91ReverseRenameSimpleCompositeOverlappingDeleteOldRdnDontExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "cn=test" );
        Rdn newRdn = new Rdn( "sn=small+cn=test" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "cn: big",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.DELETE_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "sn=small+cn=test,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertTrue( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is simple,
     * the new Rdn is composite, they overlap, with deleteOldRdn = true, and
     * some of the new values exists in the entry.
     * 
     * Covers case 9.2 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * seeAlso: big
     * sn: This is a test
     * 
     * new Rdn : cn=small+cn=test+cn=big
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test92ReverseRenameSimpleCompositeOverlappingDeleteOldRdnDontExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "cn=test" );
        Rdn newRdn = new Rdn( "sn=small+cn=test+seeAlso=big" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "seeAlso: big",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.DELETE_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 2, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "sn=small+cn=test+seeAlso=big,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );

        reversed = reverseds.get( 1 );

        assertEquals( "cn=test,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.Modify, reversed.getChangeType() );
        Modification[] mods = reversed.getModificationArray();

        assertNotNull( mods );
        assertEquals( 1, mods.length );
        assertEquals( ModificationOperation.REMOVE_ATTRIBUTE, mods[0].getOperation() );
        assertNotNull( mods[0].getAttribute() );
        assertEquals( "sn", mods[0].getAttribute().getId() );
        assertEquals( "small", mods[0].getAttribute().getString() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is composite,
     * the new Rdn is composite, they don't overlap, with deleteOldRdn = false, and
     * none of new values exists in the entry.
     * 
     * Covers case 10.1 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: sn=small+cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * cn: big
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : cn=joe+cn=plumber
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test101ReverseRenameCompositeCompositeNotOverlappingKeepOldRdnDontExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "sn=small+cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "sn=small+cn=test" );
        Rdn newRdn = new Rdn( "cn=joe+sn=plumber" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "cn: big",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.KEEP_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=joe+sn=plumber,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertTrue( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getNormName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is composite,
     * the new Rdn is composite, they don't overlap, with deleteOldRdn = false, and
     * some of the new values exists in the entry.
     * 
     * Covers case 10.2 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: sn=small+cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * cn: big
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : sn=joe+cn=big
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test102ReverseRenameCompositeCompositeNotOverlappingKeepOldRdnExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "sn=small+cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "sn=small+cn=test" );
        Rdn newRdn = new Rdn( "sn=joe+cn=big" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "cn: big",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.KEEP_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 2, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "sn=joe+cn=big,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getNormName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );

        reversed = reverseds.get( 1 );

        assertEquals( "sn=small+cn=test,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.Modify, reversed.getChangeType() );
        Modification[] mods = reversed.getModificationArray();

        assertNotNull( mods );
        assertEquals( 1, mods.length );
        assertEquals( ModificationOperation.REMOVE_ATTRIBUTE, mods[0].getOperation() );
        assertNotNull( mods[0].getAttribute() );
        assertEquals( "sn", mods[0].getAttribute().getId() );
        assertEquals( "joe", mods[0].getAttribute().getString() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is composite,
     * the new Rdn is composite, they don't overlap, with deleteOldRdn = true, and
     * none of new values exists in the entry.
     * 
     * Covers case 11.1 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: sn=small+cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * sn: big
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : cn=joe+sn=plumber
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test111ReverseRenameCompositeCompositeNotOverlappingDeleteOldRdnDontExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "sn=small+cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "sn=small+cn=test" );
        Rdn newRdn = new Rdn( "cn=joe+sn=plumber" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "sn: big",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.DELETE_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=joe+sn=plumber,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertTrue( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getNormName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is composite,
     * the new Rdn is composite, they don't overlap, with deleteOldRdn = true, and
     * some of the new values exists in the entry.
     * 
     * Covers case 11.2 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: sn=small+cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * sn: big
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : cn=joe+sn=big
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test112ReverseRenameCompositeCompositeNotOverlappingDeleteOldRdnExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "sn=small+cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "sn=small+cn=test" );
        Rdn newRdn = new Rdn( "cn=joe+sn=big" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "sn: big",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.DELETE_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 2, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "cn=joe+sn=big,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getNormName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );

        reversed = reverseds.get( 1 );

        assertEquals( "sn=small+cn=test,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.Modify, reversed.getChangeType() );
        Modification[] mods = reversed.getModificationArray();

        assertNotNull( mods );
        assertEquals( 1, mods.length );
        assertEquals( ModificationOperation.REMOVE_ATTRIBUTE, mods[0].getOperation() );
        assertNotNull( mods[0].getAttribute() );
        assertEquals( "cn", mods[0].getAttribute().getId() );
        assertEquals( "joe", mods[0].getAttribute().getString() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is composite,
     * the new Rdn is composite, they are overlapping, with deleteOldRdn = false, and
     * none of new values exists in the entry.
     * 
     * Covers case 12.1 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: sn=small+cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * cn: big
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : cn=joe+cn=test
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test121ReverseRenameCompositeCompositeOverlappingKeepOldRdnDontExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "sn=small+cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "sn=small+cn=test" );
        Rdn newRdn = new Rdn( "sn=joe+cn=test" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "cn: big",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.KEEP_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "sn=joe+cn=test,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertTrue( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getNormName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is composite,
     * the new Rdn is composite, they are overlapping, with deleteOldRdn = false, and
     * some of the new values exists in the entry.
     * 
     * Covers case 12.2 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: sn=small+cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * sn: big
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : sn=big+cn=test
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test122ReverseRenameCompositeCompositeOverlappingKeepOldRdnExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "sn=small+cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "sn=small+cn=test" );
        Rdn newRdn = new Rdn( "sn=big+cn=test" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "sn: big",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.KEEP_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "sn=big+cn=test,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getNormName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is composite,
     * the new Rdn is composite, they are overlapping, with deleteOldRdn = true, and
     * none of new values exists in the entry.
     * 
     * Covers case 13.1 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: sn=small+cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * cn: big
     * sn: small
     * sn: This is a test
     * 
     * new Rdn : sn=joe+cn=test
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test131ReverseRenameCompositeCompositeOverlappingDeleteOldRdnDontExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "sn=small+cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "sn=small+cn=test" );
        Rdn newRdn = new Rdn( "sn=joe+cn=test" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "cn: big",
            "sn: small",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.DELETE_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "sn=joe+cn=test,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertTrue( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getNormName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }


    /**
     * Test a reversed rename ModifyDN, where the initial Rdn is composite,
     * the new Rdn is composite, they are overlapping, with deleteOldRdn = true, and
     * some of the new values exists in the entry.
     * 
     * Covers case 13.1 of https://cwiki.apache.org/confluence/display/DIRxSRVx11/Reverse+LDIF
     * 
     * Initial entry
     * dn: sn=small+cn=test,ou=system
     * objectclass: top
     * objectclass: person
     * cn: test
     * sn: small
     * sn: big
     * sn: This is a test
     * 
     * new Rdn : sn=big+cn=test
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void test132ReverseRenameCompositeCompositeOverlappingDeleteOldRdnExistInEntry() throws LdapException
    {
        Dn dn = new Dn( "sn=small+cn=test,ou=system" );
        Rdn oldRdn = new Rdn( "sn=small+cn=test" );
        Rdn newRdn = new Rdn( "sn=big+cn=test" );

        Entry entry = new DefaultEntry( dn,
            "objectClass: top",
            "objectClass: person",
            "cn: test",
            "sn: small",
            "sn: big",
            "sn: this is a test" );

        List<LdifEntry> reverseds = LdifRevertor.reverseRename( entry, newRdn, LdifRevertor.DELETE_OLD_RDN );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );
        LdifEntry reversed = reverseds.get( 0 );

        assertEquals( "sn=big+cn=test,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( oldRdn.getNormName(), reversed.getNewRdn() );
        assertNull( reversed.getNewSuperior() );
    }
}
