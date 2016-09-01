/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.ldap.model.constants;


/**
 * Apache meta schema specific constants used throughout the server.
 * Final reference -&gt; class shouldn't be extended
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
//This will suppress PMD.AvoidUsingHardCodedIP warnings in this class
public final class MetaSchemaConstants
{
    /**
     *  Ensures no construction of this class, also ensures there is no need for final keyword above
     *  (Implicit super constructor is not visible for default constructor),
     *  but is still self documenting.
     */
    private MetaSchemaConstants()
    {
    }

    public static final String SCHEMA_NAME = "apachemeta";
    public static final String SCHEMA_OTHER = "other";

    // -- objectClass names --
    public static final String META_TOP_OC = "metaTop";
    public static final String META_TOP_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.1";

    public static final String META_OBJECT_CLASS_OC = "metaObjectClass";
    public static final String META_OBJECT_CLASS_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.2";

    public static final String META_ATTRIBUTE_TYPE_OC = "metaAttributeType";
    public static final String META_ATTRIBUTE_TYPE_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.3";

    public static final String META_SYNTAX_OC = "metaSyntax";
    public static final String META_SYNTAX_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.4";

    public static final String META_MATCHING_RULE_OC = "metaMatchingRule";
    public static final String META_MATCHING_RULE_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.5";

    public static final String META_DIT_STRUCTURE_RULE_OC = "metaDITStructureRule";
    public static final String META_DIT_STRUCTURE_RULE_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.6";

    public static final String META_NAME_FORM_OC = "metaNameForm";
    public static final String META_NAME_FORM_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.7";

    public static final String META_MATCHING_RULE_USE_OC = "metaMatchingRuleUse";
    public static final String META_MATCHING_RULE_USE_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.8";

    public static final String META_DIT_CONTENT_RULE_OC = "metaDITContentRule";
    public static final String META_DIT_CONTENT_RULE_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.9";

    public static final String META_SYNTAX_CHECKER_OC = "metaSyntaxChecker";
    public static final String META_SYNTAX_CHECKER_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.10";

    public static final String META_SCHEMA_OC = "metaSchema";
    public static final String META_SCHEMA_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.11";

    public static final String META_NORMALIZER_OC = "metaNormalizer";
    public static final String META_NORMALIZER_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.12";

    public static final String META_COMPARATOR_OC = "metaComparator";
    public static final String META_COMPARATOR_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.13";

    // -- attributeType names --
    public static final String M_OID_AT = "m-oid";
    public static final String M_OID_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.1 ";

    public static final String M_NAME_AT = "m-name";
    public static final String M_NAME_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.2 ";

    public static final String M_DESCRIPTION_AT = "m-description";
    public static final String M_DESCRIPTION_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.3 ";

    public static final String M_OBSOLETE_AT = "m-obsolete";
    public static final String M_OBSOLETE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.4 ";

    public static final String M_SUP_OBJECT_CLASS_AT = "m-supObjectClass";
    public static final String M_SUP_OBJECT_CLASS_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.5 ";

    public static final String M_MUST_AT = "m-must";
    public static final String M_MUST_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.6 ";

    public static final String M_MAY_AT = "m-may";
    public static final String M_MAY_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.7 ";

    public static final String M_TYPE_OBJECT_CLASS_AT = "m-typeObjectClass";
    public static final String M_TYPE_OBJECT_CLASS_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.8 ";

    public static final String M_SUP_ATTRIBUTE_TYPE_AT = "m-supAttributeType";
    public static final String M_SUP_ATTRIBUTE_TYPE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.10";

    public static final String M_EQUALITY_AT = "m-equality";
    public static final String M_EQUALITY_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.11";

    public static final String M_ORDERING_AT = "m-ordering";
    public static final String M_ORDERING_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.12";

    public static final String M_SUBSTR_AT = "m-substr";
    public static final String M_SUBSTR_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.13";

    public static final String M_SYNTAX_AT = "m-syntax";
    public static final String M_SYNTAX_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.14";

    public static final String M_SINGLE_VALUE_AT = "m-singleValue";
    public static final String M_SINGLE_VALUE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.15";

    public static final String M_COLLECTIVE_AT = "m-collective";
    public static final String M_COLLECTIVE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.16";

    public static final String M_NO_USER_MODIFICATION_AT = "m-noUserModification";
    public static final String M_NO_USER_MODIFICATION_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.17";

    public static final String M_USAGE_AT = "m-usage";
    public static final String M_USAGE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.18";

    public static final String M_RULE_ID_AT = "m-ruleId";
    public static final String M_RULE_ID_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.20";

    public static final String M_FORM_AT = "m-form";
    public static final String M_FORM_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.21";

    public static final String M_SUP_DIT_STRUCTURE_RULE_AT = "m-supDITStructureRule";
    public static final String M_SUP_DIT_STRUCTURE_RULE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.22";

    public static final String M_OC_AT = "m-oc";
    public static final String M_OC_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.24";

    public static final String M_AUX_AT = "m-aux";
    public static final String M_AUX_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.26";

    public static final String M_NOT_AT = "m-not";
    public static final String M_NOT_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.27";

    public static final String M_APPLIES_AT = "m-applies";
    public static final String M_APPLIES_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.29";

    public static final String M_MATCHING_RULE_SYNTAX_AT = "m-matchingRuleSyntax";
    public static final String M_MATCHING_RULE_SYNTAX_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.31";

    public static final String M_FQCN_AT = "m-fqcn";
    public static final String M_FQCN_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.32";

    public static final String M_BYTECODE_AT = "m-bytecode";
    public static final String M_BYTECODE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.33";

    public static final String M_DISABLED_AT = "m-disabled";
    public static final String M_DISABLED_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.37";

    public static final String M_DEPENDENCIES_AT = "m-dependencies";
    public static final String M_DEPENDENCIES_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.38";

    public static final String M_LENGTH_AT = "m-length";
    public static final String M_LENGTH_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.39";

    // -- schema extensions & values --
    public static final String X_SCHEMA_AT = "X-SCHEMA";
    public static final String X_SCHEMA_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.35";

    public static final String X_NOT_HUMAN_READABLE_AT = "X-NOT-HUMAN-READABLE";
    public static final String X_NOT_HUMAN_READABLE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.34";

    // The x-read-only extension
    public static final String X_READ_ONLY_AT = "X-READ-ONLY";
    public static final String X_READ_ONLY_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.36";
}
