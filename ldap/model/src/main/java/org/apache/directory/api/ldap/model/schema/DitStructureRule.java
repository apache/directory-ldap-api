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
package org.apache.directory.api.ldap.model.schema;


import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.i18n.I18n;


/**
 * A dITStructureRule definition. A dITStructureRules is a rule governing the
 * structure of the DIT by specifying a permitted superior to subordinate entry
 * relationship. A structure rule relates a nameForm, and therefore a STRUCTURAL
 * objectClass, to superior dITStructureRules. This permits entries of the
 * STRUCTURAL objectClass identified by the nameForm to exist in the DIT as
 * subordinates to entries governed by the indicated superior dITStructureRules.
 * Hence dITStructureRules only apply to structural object classes.
 * <p>
 * According to ldapbis [MODELS]:
 * </p>
 * 
 * <pre>
 *  DIT structure rule descriptions are written according to the ABNF:
 *  
 *    DITStructureRuleDescription = LPAREN WSP
 *        ruleid                    ; rule identifier
 *        [ SP &quot;NAME&quot; SP qdescrs ]  ; short names (descriptors)
 *        [ SP &quot;DESC&quot; SP qdstring ] ; description
 *        [ SP &quot;OBSOLETE&quot; ]         ; not active
 *        SP &quot;FORM&quot; SP oid          ; NameForm
 *        [ SP &quot;SUP&quot; ruleids ]      ; superior rules
 *        extensions WSP RPAREN     ; extensions
 * 
 *    ruleids = ruleid / ( LPAREN WSP ruleidlist WSP RPAREN )
 * 
 *    ruleidlist = ruleid *( SP ruleid )
 * 
 *    ruleid = number
 * 
 *  where:
 *    [ruleid] is the rule identifier of this DIT structure rule;
 *    NAME [qdescrs] are short names (descriptors) identifying this DIT
 *        structure rule;
 *    DESC [qdstring] is a short descriptive string;
 *    OBSOLETE indicates this DIT structure rule use is not active;
 *    FORM is specifies the name form associated with this DIT structure
 *        rule;
 *    SUP identifies superior rules (by rule id); and
 *    [extensions] describe extensions.
 *  
 *  If no superior rules are identified, the DIT structure rule applies
 *  to an autonomous administrative point (e.g. the root vertex of the
 *  subtree controlled by the subschema) [X.501].
 * </pre>
 * 
 * @see <a href="http://www.faqs.org/rfcs/rfc2252.html">RFC2252 Section 6.33</a>
 * @see <a
 *      href="http://www.ietf.org/internet-drafts/draft-ietf-ldapbis-models-11.txt">ldapbis
 *      [MODELS]</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DitStructureRule extends AbstractSchemaObject
{
    /** Declares the Serial Version Uid */
    public static final long serialVersionUID = 1L;

    /** The rule ID. A DSR does not have an OID */
    private int ruleId;

    /** The associated NameForm */
    private String form;

    /** The list of superiors rules */
    private List<Integer> superRules;


    /**
     * Creates a new instance of DitStructureRule
     * 
     * @param ruleId The RuleId for this DitStructureRule
     */
    public DitStructureRule( int ruleId )
    {
        super( SchemaObjectType.DIT_STRUCTURE_RULE, null );
        this.ruleId = ruleId;
        form = null;
        superRules = new ArrayList<>();
    }


    /**
     *  @return The associated NameForm's OID
     */
    public String getForm()
    {
        return form;
    }


    /**
     * Sets the associated NameForm's OID
     *
     * @param form The NameForm's OID
     */
    public void setForm( String form )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.form = form;
    }


    /**
     * @return The Rule ID
     */
    public int getRuleId()
    {
        return ruleId;
    }


    /**
     * Sets the rule identifier of this DIT structure rule;
     *
     * @param ruleId the rule identifier of this DIT structure rule;
     */
    public void setRuleId( int ruleId )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.ruleId = ruleId;
    }


    /**
     * @return The list of superiors RuleIDs
     */
    public List<Integer> getSuperRules()
    {
        return superRules;
    }


    /**
     * Sets the list of superior RuleIds
     * 
     * @param superRules the list of superior RuleIds
     */
    public void setSuperRules( List<Integer> superRules )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.superRules = superRules;
    }


    /**
     * Adds a new superior RuleId
     *
     * @param superRule The superior RuleID to add
     */
    public void addSuperRule( Integer superRule )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        superRules.add( superRule );
    }


    /**
     * The DIT structure rule does not have an OID
     * 
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        // We cannot throw exception here. E.g. SchemaObjectWrapper will try to use this in hashcode.
        return null;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return SchemaObjectRenderer.OPEN_LDAP_SCHEMA_RENDERER.render( this );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DitStructureRule copy()
    {
        DitStructureRule copy = new DitStructureRule( ruleId );

        // Copy the SchemaObject common data
        copy.copy( this );

        // Copy the Superiors rules
        copy.superRules = new ArrayList<>();

        // Copy the form
        copy.form = form;

        for ( int superRule : superRules )
        {
            copy.superRules.add( superRule );
        }

        return copy;
    }

    
    /**
     * @see Object#equals(Object)
     */
    @Override
    public void rehash()
    {
        int hash = h;
        
        hash = hash * 17 + ruleId;
        
        if ( form != null )
        {
            hash = hash * 17 + form.hashCode();
        }
        
        if ( superRules != null )
        {
            int tempHash = 0;
            
            for ( int superRule : superRules )
            {
                tempHash += superRule;
            }
            
            hash = hash * 17 + tempHash;
        }
        
        h = hash;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals( Object o )
    {
        if ( !super.equals( o ) )
        {
            return false;
        }

        if ( !( o instanceof DitStructureRule ) )
        {
            return false;
        }

        @SuppressWarnings("unused")
        DitStructureRule that = ( DitStructureRule ) o;

        // TODO : complete the test
        return true;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clear()
    {
        // Clear the common elements
        super.clear();

        // Clear the references
        superRules.clear();
    }
}
