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

package org.apache.directory.api.ldap.trigger;


import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.ldap.LdapContext;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.AttributeUtils;


/**
 * A utility class for working with Triggers Execution Administrative Points
 * Trigger Execution Subentries and Trigger Specifications.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class TriggerUtils
{
    /**
     * Private constructor.
     */
    private TriggerUtils()
    {
    }


    /**
     * Defines the Administration point and administrative role for the TriggerExecution specific point
     * @param apCtx The administrative point context
     * @throws NamingException If the operation failed
     */
    public static void defineTriggerExecutionSpecificPoint( LdapContext apCtx ) throws NamingException
    {
        Attributes ap = apCtx.getAttributes( "", new String[] { SchemaConstants.ADMINISTRATIVE_ROLE_AT } );
        Attribute administrativeRole = ap.get( SchemaConstants.ADMINISTRATIVE_ROLE_AT );
        
        if ( ( administrativeRole == null )
            || !AttributeUtils.containsValueCaseIgnore( administrativeRole, SchemaConstants.TRIGGER_EXECUTION_SPECIFIC_AREA ) )
        {
            Attributes changes = new BasicAttributes( SchemaConstants.ADMINISTRATIVE_ROLE_AT,
                SchemaConstants.TRIGGER_EXECUTION_SPECIFIC_AREA, true );
            apCtx.modifyAttributes( "", DirContext.ADD_ATTRIBUTE, changes );
        }
    }


    /**
     * Create the Trigger execution subentry
     * 
     * @param apCtx The administration point context
     * @param subentryCN The CN used by the suentry
     * @param subtreeSpec The subtree specification
     * @param prescriptiveTriggerSpec The prescriptive trigger specification
     * @throws NamingException If the operation failed
     */
    public static void createTriggerExecutionSubentry(
        LdapContext apCtx,
        String subentryCN,
        String subtreeSpec,
        String prescriptiveTriggerSpec ) throws NamingException
    {
        Attributes subentry = new BasicAttributes( SchemaConstants.CN_AT, subentryCN, true );
        Attribute objectClass = new BasicAttribute( SchemaConstants.OBJECT_CLASS_AT );
        subentry.put( objectClass );
        objectClass.add( SchemaConstants.TOP_OC );
        objectClass.add( SchemaConstants.SUBENTRY_OC );
        objectClass.add( SchemaConstants.TRIGGER_EXECUTION_SUBENTRY_OC );
        subentry.put( SchemaConstants.SUBTREE_SPECIFICATION_AT, subtreeSpec );
        subentry.put( SchemaConstants.PRESCRIPTIVE_TRIGGER_SPECIFICATION_AT, prescriptiveTriggerSpec );
        apCtx.createSubcontext( "cn=" + subentryCN, subentry );
    }


    /**
     * Load an prescriptive trigger specification
     * 
     * @param apCtx The administrative point context
     * @param subentryCN The subentry CN
     * @param triggerSpec The trigger specification
     * @throws NamingException If the operation failed
     */
    public static void loadPrescriptiveTriggerSpecification(
        LdapContext apCtx,
        String subentryCN,
        String triggerSpec ) throws NamingException
    {
        Attributes changes = new BasicAttributes( SchemaConstants.PRESCRIPTIVE_TRIGGER_SPECIFICATION_AT, triggerSpec, true );
        apCtx.modifyAttributes( "cn=" + subentryCN, DirContext.ADD_ATTRIBUTE, changes );
    }


    /**
     * Load the trigger specification entry
     * 
     * @param ctx The context
     * @param triggerSpec The trigger specification
     * @throws NamingException If the operation failed
     */
    public static void loadEntryTriggerSpecification(
        LdapContext ctx,
        String triggerSpec ) throws NamingException
    {
        Attributes changes = new BasicAttributes( SchemaConstants.ENTRY_TRIGGER_SPECIFICATION_AT, triggerSpec, true );
        ctx.modifyAttributes( "", DirContext.ADD_ATTRIBUTE, changes );
    }
}
