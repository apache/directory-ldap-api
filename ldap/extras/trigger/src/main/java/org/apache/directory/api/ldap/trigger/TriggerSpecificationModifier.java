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

package org.apache.directory.api.ldap.trigger;


import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.ldap.trigger.TriggerSpecification.SPSpec;


/**
 * A class used to create a Trigger Specification instance.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class TriggerSpecificationModifier
{
    /** The LDAP operation that triggered the action */
    private LdapOperation ldapOperation;

    /** The time at which the action is executed */
    private ActionTime actionTime;

    /** The list of stored procedure to execute */
    private List<SPSpec> spSpecs;


    /**
     * Instantiates a new trigger specification modifier.
     */
    public TriggerSpecificationModifier()
    {
        spSpecs = new ArrayList<>();
    }
    
    
    public TriggerSpecification create()
    {
        TriggerSpecification ts = new TriggerSpecification( ldapOperation, actionTime, spSpecs );
        
        return ts;
    }


    /**
     * Sets the action time.
     *
     * @param the action time
     */
    public void setActionTime( ActionTime actionTime )
    {
        this.actionTime = actionTime;
    }


    /**
     * Sets the LDAP operation.
     *
     * @param the LDAP operation
     */
    public void setLdapOperation( LdapOperation ldapOperation )
    {
        this.ldapOperation = ldapOperation;
    }


    /**
     * Add a stored procedure spec.
     *
     * @param the stored procedure spec to add
     */
    public void addSPSpec( SPSpec spSpec )
    {
        spSpecs.add( spSpec );
    }
    
    
    /**
     * The stored procedure spec modifier
     */
    public static class SPSpecModifier
    {
        private String name;

        private List<StoredProcedureOption> options = new ArrayList<>();

        private List<StoredProcedureParameter> parameters = new ArrayList<>();


        /**
         * Instantiates a new stored procedure spec.
         */
        public SPSpecModifier()
        {
        }


        /**
         * Set the name.
         *
         * @param the name
         */
        public void setName( String name )
        {
            this.name = name;
        }


        /**
         * Add an option.
         *
         * @param option the option
         */
        public void addOption( StoredProcedureOption option )
        {
            options.add( option );
        }


        /**
         * Add a parameter.
         *
         * @param parameter the parameter
         */
        public void addParameter( StoredProcedureParameter parameter )
        {
            parameters.add( parameter );
        }
        
        
        public SPSpec getSPSpec()
        {
            return new SPSpec( name, options, parameters );
        }
    }
}
