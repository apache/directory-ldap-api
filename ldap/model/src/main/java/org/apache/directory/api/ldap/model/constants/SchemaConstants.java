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
package org.apache.directory.api.ldap.model.constants;


/**
 * A utility class where we declare all the schema objects being used by any
 * ldap server.
 * Final reference -> class shouldn't be extended
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class SchemaConstants
{
    /**
     *  Ensures no construction of this class, also ensures there is no need for final keyword above
     *  (Implicit super constructor is not visible for default constructor),
     *  but is still self documenting.
     */
    private SchemaConstants()
    {
    }

    // SchemaEntity names
    public static final String ATTRIBUTE_TYPE = "AttributeType";
    public static final String COMPARATOR = "Comparator";
    public static final String DIT_CONTENT_RULE = "DitContentRule";
    public static final String DIT_STRUCTURE_RULE = "DitStructureRule";
    public static final String MATCHING_RULE = "MatchingRule";
    public static final String MATCHING_RULE_USE = "MatchingRuleUse";
    public static final String NAME_FORM = "NameForm";
    public static final String NORMALIZER = "Normalizer";
    public static final String OBJECT_CLASS = "ObjectCLass";
    public static final String SYNTAX = "Syntax";
    public static final String SYNTAX_CHECKER = "SyntaxChecker";

    // SchemaEntity paths
    public static final String ATTRIBUTE_TYPES_PATH = "ou=attributetypes";
    public static final String COMPARATORS_PATH = "ou=comparators";
    public static final String DIT_CONTENT_RULES_PATH = "ou=ditcontentrules";
    public static final String DIT_STRUCTURE_RULES_PATH = "ou=ditstructurerules";
    public static final String MATCHING_RULES_PATH = "ou=matchingrules";
    public static final String MATCHING_RULE_USE_PATH = "ou=matchingruleuse";
    public static final String NAME_FORMS_PATH = "ou=nameforms";
    public static final String NORMALIZERS_PATH = "ou=normalizers";
    public static final String OBJECT_CLASSES_PATH = "ou=objectclasses";
    public static final String SYNTAXES_PATH = "ou=syntaxes";
    public static final String SYNTAX_CHECKERS_PATH = "ou=syntaxcheckers";

    // Schema root
    public static final String OU_SCHEMA = "ou=schema";

    // The Dn for the schema modifications
    public static final String SCHEMA_MODIFICATIONS_DN = "ou=schemaModifications,ou=schema";

    // Special attributes 1.1 , * and + for search operations
    public static final String NO_ATTRIBUTE = "1.1";
    public static final String[] NO_ATTRIBUTE_ARRAY = new String[]
        { NO_ATTRIBUTE };

    public static final String ALL_USER_ATTRIBUTES = "*";
    public static final String[] ALL_USER_ATTRIBUTES_ARRAY = new String[]
        { ALL_USER_ATTRIBUTES };

    public static final String ALL_OPERATIONAL_ATTRIBUTES = "+";
    public static final String[] ALL_OPERATIONAL_ATTRIBUTES_ARRAY = new String[]
        { ALL_OPERATIONAL_ATTRIBUTES };

    public static final String[] ALL_ATTRIBUTES_ARRAY = new String[]
        { ALL_OPERATIONAL_ATTRIBUTES, ALL_USER_ATTRIBUTES };

    // ---- ObjectClasses -----------------------------------------------------
    // Domain
    public static final String DOMAIN_OC = "domain";
    public static final String DOMAIN_OC_OID = "0.9.2342.19200300.100.4.13";

    // PosixAccount
    public static final String POSIX_ACCOUNT_OC = "posicAccount";
    public static final String POSIX_ACCOUNT_OC_OID = "1.3.6.1.1.1.2.0";

    // PosixGroup
    public static final String POSIX_GROUP_OC = "posixGroup";
    public static final String POSIX_GROUP_OC_OID = "1.3.6.1.1.1.2.2";

    // ExtensibleObject
    public static final String EXTENSIBLE_OBJECT_OC = "extensibleObject";
    public static final String EXTENSIBLE_OBJECT_OC_OID = "1.3.6.1.4.1.1466.101.120.111";

    // DcObject
    public static final String DC_OBJECT_OC = "dcObject";
    public static final String DC_OBJECT_OC_OID = "1.3.6.1.4.1.1466.344";

    // Apache Meta Schema
    // MetaTop
    public static final String META_TOP_OC = "metaTop";
    public static final String META_TOP_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.1";

    // MetaObjectClass
    public static final String META_OBJECT_CLASS_OC = "metaObjectClass";
    public static final String META_OBJECT_CLASS_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.2";

    // MetaAttributeType
    public static final String META_ATTRIBUTE_TYPE_OC = "metaAttributeType";
    public static final String META_ATTRIBUTE_TYPE_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.3";

    // MetaSyntax
    public static final String META_SYNTAX_OC = "metaSyntax";
    public static final String META_SYNTAX_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.4";

    // MetaMatchingRule
    public static final String META_MATCHING_RULE_OC = "metaMatchingRule";
    public static final String META_MATCHING_RULE_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.5";

    // MetaDITStructureRule
    public static final String META_DIT_STRUCTURE_RULE_OC = "metaDITStructureRule";
    public static final String META_DIT_STRUCTURE_RULE_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.6";

    // MetaNameForm
    public static final String META_NAME_FORM_OC = "metaNameForm";
    public static final String META_NAME_FORM_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.7";

    // MetaMatchingRuleUse
    public static final String META_MATCHING_RULE_USE_OC = "metaMatchingRuleUse";
    public static final String META_MATCHING_RULE_USE_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.8";

    // MetaDITContentRule
    public static final String META_DIT_CONTENT_RULE_OC = "metaDITContentRule";
    public static final String META_DIT_CONTENT_RULE_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.9";

    // MetaSyntaxChecker
    public static final String META_SYNTAX_CHECKER_OC = "metaSyntaxChecker";
    public static final String META_SYNTAX_CHECKER_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.10";

    // MetaSchema
    public static final String META_SCHEMA_OC = "metaSchema";
    public static final String META_SCHEMA_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.11";

    // MetaNormalizer
    public static final String META_NORMALIZER_OC = "metaNormalizer";
    public static final String META_NORMALIZER_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.12";

    // MetaComparator
    public static final String META_COMPARATOR_OC = "metaComparator";
    public static final String META_COMPARATOR_OC_OID = "1.3.6.1.4.1.18060.0.4.0.3.13";

    // Krb5Principal
    public static final String KRB5_PRINCIPAL_OC = "krb5Principal";
    public static final String KRB5_PRINCIPAL_OC_OID = "1.3.6.1.4.1.5322.10.2.1";

    // Top
    public static final String TOP_OC = "top";
    public static final String TOP_OC_OID = "2.5.6.0";

    // Alias
    public static final String ALIAS_OC = "alias";
    public static final String ALIAS_OC_OID = "2.5.6.1";

    // Country
    public static final String COUNTRY_OC = "country";
    public static final String COUNTRY_OC_OID = "2.5.6.2";

    // Locality
    public static final String LOCALITY_OC = "locality";
    public static final String LOCALITY_OC_OID = "2.5.6.3";

    // Organization
    public static final String ORGANIZATION_OC = "organization";
    public static final String ORGANIZATION_OC_OID = "2.5.6.4";

    // OrganizationalUnit
    public static final String ORGANIZATIONAL_UNIT_OC = "organizationalUnit";
    public static final String ORGANIZATIONAL_UNIT_OC_OID = "2.5.6.5";

    // Person
    public static final String PERSON_OC = "person";
    public static final String PERSON_OC_OID = "2.5.6.6";
    // OrganizationalPerson
    public static final String ORGANIZATIONAL_PERSON_OC = "organizationalPerson";
    public static final String ORGANIZATIONAL_PERSON_OC_OID = "2.5.6.7";

    // OrganizationalRole
    public static final String ORGANIZATIONAL_ROLE_OC = "organizationalRole";
    public static final String ORGANIZATIONAL_ROLE_OC_OID = "2.5.6.8";

    // GroupOfNames
    public static final String GROUP_OF_NAMES_OC = "groupOfNames";
    public static final String GROUP_OF_NAMES_OC_OID = "2.5.6.9";

    // ResidentialPerson
    public static final String RESIDENTIAL_PERSON_OC = "residentialPerson";
    public static final String RESIDENTIAL_PERSON_OC_OID = "2.5.6.10";

    // GroupOfUniqueNames
    public static final String GROUP_OF_UNIQUE_NAMES_OC = "groupOfUniqueNames";
    public static final String GROUP_OF_UNIQUE_NAMES_OC_OID = "2.5.6.17";

    // Subentry
    public static final String SUBENTRY_OC = "subentry";
    public static final String SUBENTRY_OC_OID = "2.5.17.0";

    // AccessControlSubentry
    public static final String ACCESS_CONTROL_SUBENTRY_OC = "accessControlSubentry";
    public static final String ACCESS_CONTROL_SUBENTRY_OC_OID = "2.5.17.1";

    // CollectiveAttributeSubentry
    public static final String COLLECTIVE_ATTRIBUTE_SUBENTRY_OC = "collectiveAttributeSubentry";
    public static final String COLLECTIVE_ATTRIBUTE_SUBENTRY_OC_OID = "2.5.17.2";

    // Subschema
    public static final String SUBSCHEMA_OC = "subschema";
    public static final String SUBSCHEMA_OC_OID = "2.5.20.1";

    // InetOrgPerson
    public static final String INET_ORG_PERSON_OC = "inetOrgPerson";
    public static final String INET_ORG_PERSON_OC_OID = "2.16.840.1.113730.3.2.2";

    // Referral
    public static final String REFERRAL_OC = "referral";
    public static final String REFERRAL_OC_OID = "2.16.840.1.113730.3.2.6";

    // ---- AttributeTypes ----------------------------------------------------
    // Uid
    public static final String UID_AT = "uid";
    public static final String USER_ID_AT = "userid";
    public static final String UID_AT_OID = "0.9.2342.19200300.100.1.1";

    // DomainComponent
    public static final String DC_AT = "dc";
    public static final String DOMAIN_COMPONENT_AT = "domainComponent";
    public static final String DOMAIN_COMPONENT_AT_OID = "0.9.2342.19200300.100.1.25";

    // UidObject
    public static final String UID_OBJECT_AT = "uidObject";
    public static final String UID_OBJECT_AT_OID = "1.3.6.1.1.3.1";

    // VendorName
    public static final String VENDOR_NAME_AT = "vendorName";
    public static final String VENDOR_NAME_AT_OID = "1.3.6.1.1.4";

    // VendorVersion
    public static final String VENDOR_VERSION_AT = "vendorVersion";
    public static final String VENDOR_VERSION_AT_OID = "1.3.6.1.1.5";

    // entryUUID
    public static final String ENTRY_UUID_AT = "entryUUID";
    public static final String ENTRY_UUID_AT_OID = "1.3.6.1.1.16.4";

    // entryParentId
    public static final String ENTRY_PARENT_ID_AT = "entryParentId";
    public static final String ENTRY_PARENT_ID_OID = "1.3.6.1.4.1.18060.0.4.1.2.51";

    // entryDN
    public static final String ENTRY_DN_AT = "entryDN";
    public static final String ENTRY_DN_AT_OID = "1.3.6.1.1.20";

    // NamingContexts
    public static final String NAMING_CONTEXTS_AT = "namingContexts";
    public static final String NAMING_CONTEXTS_AT_OID = "1.3.6.1.4.1.1466.101.120.5";

    // SupportedExtension
    public static final String SUPPORTED_EXTENSION_AT = "supportedExtension";
    public static final String SUPPORTED_EXTENSION_AT_OID = "1.3.6.1.4.1.1466.101.120.7";

    // supportedControl
    public static final String SUPPORTED_CONTROL_AT = "supportedControl";
    public static final String SUPPORTED_CONTROL_AT_OID = "1.3.6.1.4.1.1466.101.120.13";

    // supportedSASLMechanisms
    public static final String SUPPORTED_SASL_MECHANISMS_AT = "supportedSASLMechanisms";
    public static final String SUPPORTED_SASL_MECHANISMS_AT_OID = "1.3.6.1.4.1.1466.101.120.14";

    // SupportedLdapVersion
    public static final String SUPPORTED_LDAP_VERSION_AT = "supportedLDAPVersion";
    public static final String SUPPORTED_LDAP_VERSION_AT_OID = "1.3.6.1.4.1.1466.101.120.15";

    // LdapSyntaxes
    public static final String LDAP_SYNTAXES_AT = "ldapSyntaxes";
    public static final String LDAP_SYNTAXES_AT_OID = "1.3.6.1.4.1.1466.101.120.16";

    // SupportedFeatures
    public static final String SUPPORTED_FEATURES_AT = "supportedFeatures";
    public static final String SUPPORTED_FEATURES_AT_OID = "1.3.6.1.4.1.4203.1.3.5";

    // entryCSN
    public static final String ENTRY_CSN_AT = "entryCSN";
    public static final String ENTRY_CSN_AT_OID = "1.3.6.1.4.1.4203.666.1.7";

    // contextCSN
    public static final String CONTEXT_CSN_AT = "contextCSN";
    public static final String CONTEXT_CSN_AT_OID = "1.3.6.1.4.1.4203.666.1.25";

    // AccessControlSubentries
    public static final String ACCESS_CONTROL_SUBENTRIES_AT = "accessControlSubentries";
    public static final String ACCESS_CONTROL_SUBENTRIES_AT_OID = "1.3.6.1.4.1.18060.0.4.1.2.11";

    // TriggerExecutionSubentries
    public static final String TRIGGER_EXECUTION_SUBENTRIES_AT = "triggerExecutionSubentries";
    public static final String TRIGGER_EXECUTION_SUBENTRIES_AT_OID = "1.3.6.1.4.1.18060.0.4.1.2.27";

    // Comparators
    public static final String COMPARATORS_AT = "comparators";
    public static final String COMPARATORS_AT_OID = "1.3.6.1.4.1.18060.0.4.1.2.32";

    // Normalizers
    public static final String NORMALIZERS_AT = "normalizers";
    public static final String NORMALIZERS_AT_OID = "1.3.6.1.4.1.18060.0.4.1.2.33";

    // SyntaxCheckers
    public static final String SYNTAX_CHECKERS_AT = "syntaxCheckers";
    public static final String SYNTAX_CHECKERS_AT_OID = "1.3.6.1.4.1.18060.0.4.1.2.34";

    // ChangeLogContext
    public static final String CHANGELOG_CONTEXT_AT = "changeLogContext";
    public static final String CHANGELOG_CONTEXT_AT_OID = "1.3.6.1.4.1.18060.0.4.1.2.49";

    // ObjectClass
    public static final String OBJECT_CLASS_AT = "objectClass";
    public static final String OBJECT_CLASS_AT_OID = "2.5.4.0";

    // AliasedObjectName
    public static final String ALIASED_OBJECT_NAME_AT = "aliasedObjectName";
    public static final String ALIASED_OBJECT_NAME_AT_OID = "2.5.4.1";

    // Cn
    public static final String CN_AT = "cn";
    public static final String COMMON_NAME_AT = "commonName";
    public static final String CN_AT_OID = "2.5.4.3";

    // Sn
    public static final String SN_AT = "sn";
    public static final String SURNAME_AT = "surname";
    public static final String SN_AT_OID = "2.5.4.4";

    // St
    public static final String ST_AT = "st";
    public static final String STATEORPROVINCE_NAME_AT = "stateOrProvinceName";
    public static final String ST_AT_OID = "2.5.4.8";

    // Street
    public static final String STREET_AT = "street";
    public static final String STREET_ADDRESS_AT = "streetAddress";
    public static final String STREET_AT_OID = "2.5.4.9";

    // O
    public static final String O_AT = "o";
    public static final String ORGANIZATION_NAME_AT = "organizationName";
    public static final String O_AT_OID = "2.5.4.10";

    // Ou
    public static final String OU_AT = "ou";
    public static final String ORGANIZATIONAL_UNIT_NAME_AT = "organizationalUnitName";
    public static final String OU_AT_OID = "2.5.4.11";

    // SearchGuide
    public static final String SEARCHGUIDE_AT = "searchguide";
    public static final String SEARCHGUIDE_AT_OID = "2.5.4.14";

    // PostalCode
    public static final String POSTALCODE_AT = "postalCode";
    public static final String POSTALCODE_AT_OID = "2.5.4.17";

    // PostalCode
    public static final String C_POSTALCODE_AT = "c-postalCode";
    public static final String C_POSTALCODE_AT_OID = "2.5.4.17.1";

    // PostOfficeBox
    public static final String POSTOFFICEBOX_AT = "postOfficeBox";
    public static final String POSTOFFICEBOX_AT_OID = "2.5.4.18";

    // Member
    public static final String MEMBER_AT = "member";
    public static final String MEMBER_AT_OID = "2.5.4.31";

    // UserPassword
    public static final String USER_PASSWORD_AT = "userPassword";
    public static final String USER_PASSWORD_AT_OID = "2.5.4.35";

    // Name
    public static final String NAME_AT = "name";
    public static final String NAME_AT_OID = "2.5.4.41";

    // UniqueMember
    public static final String UNIQUE_MEMBER_AT = "uniqueMember";
    public static final String UNIQUE_MEMBER_AT_OID = "2.5.4.50";

    // ExcludeAllColectiveAttributes
    public static final String EXCLUDE_ALL_COLLECTIVE_ATTRIBUTES_AT = "excludeAllCollectiveAttributes";
    public static final String EXCLUDE_ALL_COLLECTIVE_ATTRIBUTES_AT_OID = "2.5.18.0";

    // CreateTimestamp
    public static final String CREATE_TIMESTAMP_AT = "createTimestamp";
    public static final String CREATE_TIMESTAMP_AT_OID = "2.5.18.1";

    // ModifyTimestamp
    public static final String MODIFY_TIMESTAMP_AT = "modifyTimestamp";
    public static final String MODIFY_TIMESTAMP_AT_OID = "2.5.18.2";

    // CreatorsName
    public static final String CREATORS_NAME_AT = "creatorsName";
    public static final String CREATORS_NAME_AT_OID = "2.5.18.3";

    // ModifiersName
    public static final String MODIFIERS_NAME_AT = "modifiersName";
    public static final String MODIFIERS_NAME_AT_OID = "2.5.18.4";

    // AdministrativeRole
    public static final String ADMINISTRATIVE_ROLE_AT = "administrativeRole";
    public static final String ADMINISTRATIVE_ROLE_AT_OID = "2.5.18.5";

    // SubtreeSpecification
    public static final String SUBTREE_SPECIFICATION_AT = "subtreeSpecification";
    public static final String SUBTREE_SPECIFICATION_AT_OID = "2.5.18.6";

    // CollectiveExclusions
    public static final String COLLECTIVE_EXCLUSIONS_AT = "collectiveExclusions";
    public static final String COLLECTIVE_EXCLUSIONS_AT_OID = "2.5.18.7";

    // hasSubordinates
    public static final String HAS_SUBORDINATES_AT = "hasSubordinates";
    public static final String HAS_SUBORDINATES_AT_OID = "2.5.18.9";

    // SubschemaSubentry
    public static final String SUBSCHEMA_SUBENTRY_AT = "subschemaSubentry";
    public static final String SUBSCHEMA_SUBENTRY_AT_OID = "2.5.18.10";

    // CollectiveAttributeSubentries
    public static final String COLLECTIVE_ATTRIBUTE_SUBENTRIES_AT = "collectiveAttributeSubentries";
    public static final String COLLECTIVE_ATTRIBUTE_SUBENTRIES_AT_OID = "2.5.18.12";

    // DitStructureRules
    public static final String DIT_STRUCTURE_RULES_AT = "ditStructureRules";
    public static final String DIT_STRUCTURE_RULES_AT_OID = "2.5.21.1";

    // DitContentRules
    public static final String DIT_CONTENT_RULES_AT = "ditContentRules";
    public static final String DIT_CONTENT_RULES_AT_OID = "2.5.21.2";

    // MatchingRules
    public static final String MATCHING_RULES_AT = "matchingRules";
    public static final String MATCHING_RULES_AT_OID = "2.5.21.4";

    // AttributeTypes
    public static final String ATTRIBUTE_TYPES_AT = "attributeTypes";
    public static final String ATTRIBUTE_TYPES_AT_OID = "2.5.21.5";

    // ObjectClasses
    public static final String OBJECT_CLASSES_AT = "objectClasses";
    public static final String OBJECT_CLASSES_AT_OID = "2.5.21.6";

    // NameForms
    public static final String NAME_FORMS_AT = "nameForms";
    public static final String NAME_FORMS_AT_OID = "2.5.21.7";

    // MatchingRuleUse
    public static final String MATCHING_RULE_USE_AT = "matchingRuleUse";
    public static final String MATCHING_RULE_USE_AT_OID = "2.5.21.8";

    // StructuralObjectClass
    public static final String STRUCTURAL_OBJECT_CLASS_AT = "structuralObjectClass";
    public static final String STRUCTURAL_OBJECT_CLASS_AT_OID = "2.5.21.9";

    // governingStructureRule
    public static final String GOVERNING_STRUCTURE_RULE_AT = "governingStructureRule";
    public static final String GOVERNING_STRUCTURE_RULE_AT_OID = "2.5.21.10";

    // AccessControlScheme
    public static final String ACCESS_CONTROL_SCHEME_AT = "accessControlScheme";
    public static final String ACCESS_CONTROL_SCHEME_OID = "2.5.24.1";

    // PrescriptiveACI
    public static final String PRESCRIPTIVE_ACI_AT = "prescriptiveACI";
    public static final String PRESCRIPTIVE_ACI_AT_OID = "2.5.24.4";

    // EntryACI
    public static final String ENTRY_ACI_AT = "entryACI";
    public static final String ENTRY_ACI_AT_OID = "2.5.24.5";

    // SubentryACI
    public static final String SUBENTRY_ACI_AT = "subentryACI";
    public static final String SUBENTRY_ACI_AT_OID = "2.5.24.6";

    // Ref
    public static final String REF_AT = "ref";
    public static final String REF_AT_OID = "2.16.840.1.113730.3.1.34";

    // DisplayName
    public static final String DISPLAY_NAME_AT = "displayName";
    public static final String DISPLAY_NAME_AT_OID = "2.16.840.1.113730.3.1.241";

    // numSubordinates, by Sun
    public static final String NUM_SUBORDINATES_AT = "numSubordinates";
    // no official OID in RFCs

    // subordinateCount, by Novell
    public static final String SUBORDINATE_COUNT_AT = "subordinateCount";
    // no official OID in RFCs

    //=========================================================================
    // LdapServer AT and OC
    //-------------------------------------------------------------------------
    // ObjectClasses
    //-------------------------------------------------------------------------

    //=========================================================================
    // DirectoryService AT and OC
    //-------------------------------------------------------------------------
    // ads-directoryServiceId AT
    public static final String ADS_DIRECTORY_SERVICE_ID = "ads-directoryServiceId";
    public static final String ADS_DIRECTORY_SERVICE_ID_OID = "1.3.6.1.4.1.18060.0.4.1.2.100";

    //=========================================================================
    // Replication AT and OC
    //-------------------------------------------------------------------------
    // ObjectClasses
    //-------------------------------------------------------------------------
    // ads-replEventLog OC
    public static final String ADS_REPL_EVENT_LOG = "ads-replEventLog";
    public static final String ADS_REPL_EVENT_LOG_OID = "1.3.6.1.4.1.18060.0.4.1.3.805";

    // ads-replConsumer OC
    public static final String ADS_REPL_CONSUMER = "ads-replConsumer";
    public static final String ADS_REPL_CONSUMER_OID = "1.3.6.1.4.1.18060.0.4.1.3.806";

    //-------------------------------------------------------------------------
    // AttributeTypes
    //-------------------------------------------------------------------------
    // ads-dsReplicaId AT
    public static final String ADS_DS_REPLICA_ID = "ads-dsReplicaId";
    public static final String ADS_DS_REPLICA_ID_OID = "1.3.6.1.4.1.18060.0.4.1.2.112";

    // ads-replConsumerImpl AT
    public static final String ADS_REPL_CONSUMER_IMPL = "ads-replConsumerImpl";
    public static final String ADS_REPL_CONSUMER_IMPL_OID = "1.3.6.1.4.1.18060.0.4.1.2.310";

    // ads-replSearchFilter AT
    public static final String ADS_REPL_SEARCH_FILTER = "ads-replSearchFilter";
    public static final String ADS_REPL_SEARCH_FILTER_OID = "1.3.6.1.4.1.18060.0.4.1.2.817";

    // ads-replLastSentCsn AT
    public static final String ADS_REPL_LAST_SENT_CSN = "ads-replLastSentCsn";
    public static final String ADS_REPL_LAST_SENT_CSN_OID = "1.3.6.1.4.1.18060.0.4.1.2.818";

    // ads-replAliasDerefMode AT
    public static final String ADS_REPL_ALIAS_DEREF_MODE = "ads-replAliasDerefMode";
    public static final String ADS_REPL_ALIAS_DEREF_MODE_OID = "1.3.6.1.4.1.18060.0.4.1.2.819";

    // ads-searchBaseDN AT
    public static final String ADS_SEARCH_BASE_DN = "ads-searchBaseDN";
    public static final String ADS_SEARCH_BASE_DN_OID = "1.3.6.1.4.1.18060.0.4.1.2.820";

    // ads-replSearchScope AT
    public static final String ADS_REPL_SEARCH_SCOPE = "ads-replSearchScope";
    public static final String ADS_REPL_SEARCH_SCOPE_OID = "1.3.6.1.4.1.18060.0.4.1.2.821";

    // ads-replRefreshNPersist AT
    public static final String ADS_REPL_REFRESH_N_PERSIST = "ads-replRefreshNPersist";
    public static final String ADS_REPL_REFRESH_N_PERSIST_OID = "1.3.6.1.4.1.18060.0.4.1.2.822";

    // ads-replProvHostName AT
    public static final String ADS_REPL_PROV_HOST_NAME = "ads-replProvHostName";
    public static final String ADS_REPL_PROV_HOST_NAME_OID = "1.3.6.1.4.1.18060.0.4.1.2.823";

    // ads-replProvPort AT
    public static final String ADS_REPL_PROV_PORT = "ads-replProvPort";
    public static final String ADS_REPL_PROV_PORT_OID = "1.3.6.1.4.1.18060.0.4.1.2.824";

    // ads-replUserDn AT
    public static final String ADS_REPL_USER_DN = "ads-replUserDn";
    public static final String ADS_REPL_USER_DN_OID = "1.3.6.1.4.1.18060.0.4.1.2.825";

    // ads-replUserPassword AT
    public static final String ADS_REPL_USER_PASSWORD = "ads-replUserPassword";
    public static final String ADS_REPL_USER_PASSWORD_OID = "1.3.6.1.4.1.18060.0.4.1.2.826";

    // ads-replRefreshInterval AT
    public static final String ADS_REPL_REFRESH_INTERVAL = "ads-replRefreshInterval";
    public static final String ADS_REPL_REFRESH_INTERVAL_OID = "1.3.6.1.4.1.18060.0.4.1.2.827";

    // ads-replAttributes AT
    public static final String ADS_REPL_ATTRIBUTES = "ads-replAttributes";
    public static final String ADS_REPL_ATTRIBUTES_OID = "1.3.6.1.4.1.18060.0.4.1.2.828";

    // ads-replSearchSizeLimit AT
    public static final String ADS_REPL_SEARCH_SIZE_LIMIT = "ads-replSearchSizeLimit";
    public static final String ADS_REPL_SEARCH_SIZE_LIMIT_OID = "1.3.6.1.4.1.18060.0.4.1.2.829";

    // ads-replSearchTimeOut AT
    public static final String ADS_REPL_SEARCH_TIMEOUT = "ads-replSearchTimeOut";
    public static final String ADS_REPL_SEARCH_TIMEOUT_OID = "1.3.6.1.4.1.18060.0.4.1.2.830";

    // ads-replCookie AT
    public static final String ADS_REPL_COOKIE = "ads-replCookie";
    public static final String ADS_REPL_COOKIE_OID = "1.3.6.1.4.1.18060.0.4.1.2.831";

    // ads-replReqHandler AT
    public static final String ADS_REPL_REQ_HANDLER = "ads-replReqHandler";
    public static final String ADS_REPL_REQ_HANDLER_OID = "1.3.6.1.4.1.18060.0.4.1.2.832";

    // ads-replUseTls AT
    public static final String ADS_REPL_USE_TLS = "ads-replUseTls";
    public static final String ADS_REPL_USE_TLS_OID = "1.3.6.1.4.1.18060.0.4.1.2.833";

    // ads-replStrictCertValidation AT
    public static final String ADS_REPL_STRICT_CERT_VALIDATION = "ads-replStrictCertValidation";
    public static final String ADS_REPL_STRICT_CERT_VALIDATION_OID = "1.3.6.1.4.1.18060.0.4.1.2.834";

    // ads-replProviderId AT
    public static final String ADS_REPL_PROVIDER_ID = "ads-replProviderId";
    public static final String ADS_REPL_PROVIDER_ID_OID = "1.3.6.1.4.1.18060.0.4.1.2.836";

    // ads-replConsumerId AT
    public static final String ADS_REPL_CONSUMER_ID = "ads-replConsumerId";
    public static final String ADS_REPL_CONSUMER_ID_OID = "1.3.6.1.4.1.18060.0.4.1.2.837";

    // ads-replEnabled AT
    public static final String ADS_REPL_ENABLED = "ads-replEnabled";
    public static final String ADS_REPL_ENABLED_OID = "1.3.6.1.4.1.18060.0.4.1.2.838";

    // ads-replLogMaxIdle AT
    public static final String ADS_REPL_LOG_MAX_IDLE = "ads-replLogMaxIdle";
    public static final String ADS_REPL_LOG_MAX_IDLE_OID = "1.3.6.1.4.1.18060.0.4.1.2.920";

    // ads-replLogPurgeThresholdCount AT
    public static final String ADS_REPL_LOG_PURGE_THRESHOLD_COUNT = "ads-replLogPurgeThresholdCount";
    public static final String ADS_REPL_LOG_PURGE_THRESHOLD_COUNT_OID = "1.3.6.1.4.1.18060.0.4.1.2.922";

    //-------------------------------------------------------------------------
    // ---- Syntaxes ----------------------------------------------------------
    //-------------------------------------------------------------------------
    public static final String NAME_OR_NUMERIC_ID_SYNTAX = "1.3.6.1.4.1.18060.0.4.0.0.0";

    public static final String OBJECT_CLASS_TYPE_SYNTAX = "1.3.6.1.4.1.18060.0.4.0.0.1";

    public static final String NUMERIC_OID_SYNTAX = "1.3.6.1.4.1.18060.0.4.0.0.2";

    public static final String ATTRIBUTE_TYPE_USAGE_SYNTAX = "1.3.6.1.4.1.18060.0.4.0.0.3";

    // RFC 4517, par. 3.3.23
    public static final String NUMBER_SYNTAX = "1.3.6.1.4.1.18060.0.4.0.0.4";

    public static final String OID_LEN_SYNTAX = "1.3.6.1.4.1.18060.0.4.0.0.5";

    public static final String OBJECT_NAME_SYNTAX = "1.3.6.1.4.1.18060.0.4.0.0.6";

    // RFC 2252, removed in RFC 4517
    public static final String ACI_ITEM_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.1";

    // RFC 2252, removed in RFC 4517
    public static final String ACCESS_POINT_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.2";

    // RFC 4517, chap 3.3.1
    public static final String ATTRIBUTE_TYPE_DESCRIPTION_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.3";

    // RFC 2252, removed in RFC 4517
    public static final String AUDIO_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.4";

    // RFC 2252, removed in RFC 4517
    public static final String BINARY_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.5";

    // RFC 4517, chap 3.3.2
    public static final String BIT_STRING_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.6";

    // RFC 4517, chap 3.3.3
    public static final String BOOLEAN_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.7";

    // RFC 2252, removed in RFC 4517, reintroduced in RFC 4523, chap. 2.1
    public static final String CERTIFICATE_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.8";

    // RFC 2252, removed in RFC 4517, reintroduced in RFC 4523, chap. 2.2
    public static final String CERTIFICATE_LIST_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.9";

    // RFC 2252, removed in RFC 4517, reintroduced in RFC 4523, chap. 2.3
    public static final String CERTIFICATE_PAIR_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.10";

    // RFC 4517, chap 3.3.4
    public static final String COUNTRY_STRING_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.11";

    // RFC 4517, chap 3.3.9
    public static final String DN_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.12";

    // RFC 2252, removed in RFC 4517
    public static final String DATA_QUALITY_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.13";

    // RFC 4517, chap 3.3.5
    public static final String DELIVERY_METHOD_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.14";

    // RFC 4517, chap 3.3.6
    public static final String DIRECTORY_STRING_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.15";

    // RFC 4517, chap 3.3.7
    public static final String DIT_CONTENT_RULE_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.16";

    // RFC 4517, chap 3.3.8
    public static final String DIT_STRUCTURE_RULE_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.17";

    // RFC 2252, removed in RFC 4517
    public static final String DL_SUBMIT_PERMISSION_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.18";

    // RFC 2252, removed in RFC 4517
    public static final String DSA_QUALITY_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.19";

    // RFC 2252, removed in RFC 4517
    public static final String DSE_TYPE_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.20";

    // RFC 4517, chap 3.3.10
    public static final String ENHANCED_GUIDE_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.21";

    // RFC 4517, chap 3.3.11
    public static final String FACSIMILE_TELEPHONE_NUMBER_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.22";

    // RFC 4517, chap 3.3.12
    public static final String FAX_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.23";

    // RFC 4517, chap 3.3.13
    public static final String GENERALIZED_TIME_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.24";

    // RFC 4517, chap 3.3.14
    public static final String GUIDE_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.25";

    // RFC 4517, chap 3.3.15
    public static final String IA5_STRING_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.26";

    // RFC 4517, chap 3.3.16
    public static final String INTEGER_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.27";

    // RFC 4517, chap 3.3.17
    public static final String JPEG_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.28";

    // RFC 2252, removed in RFC 4517
    public static final String MASTER_AND_SHADOW_ACCESS_POINTS_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.29";

    // RFC 4517, chap 3.3.19
    public static final String MATCHING_RULE_DESCRIPTION_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.30";

    // RFC 4517, chap 3.3.20
    public static final String MATCHING_RULE_USE_DESCRIPTION_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.31";

    // RFC 2252, removed in RFC 4517
    public static final String MAIL_PREFERENCE_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.32";

    // RFC 2252, removed in RFC 4517
    public static final String MHS_OR_ADDRESS_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.33";

    // RFC 4517, chap 3.3.21
    public static final String NAME_AND_OPTIONAL_UID_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.34";

    // RFC 4517, chap 3.3.22
    public static final String NAME_FORM_DESCRIPTION_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.35";

    // RFC 4517, chap 3.3.23
    public static final String NUMERIC_STRING_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.36";

    // RFC 4517, chap 3.3.24
    public static final String OBJECT_CLASS_DESCRIPTION_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.37";

    // RFC 4517, chap 3.3.26
    public static final String OID_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.38";

    // RFC 4517, chap 3.3.27
    public static final String OTHER_MAILBOX_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.39";

    // RFC 4517, chap 3.3.25
    public static final String OCTET_STRING_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.40";

    // RFC 4517, chap 3.3.28
    public static final String POSTAL_ADDRESS_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.41";

    // RFC 2252, removed in RFC 4517
    public static final String PROTOCOL_INFORMATION_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.42";

    // RFC 2252, removed in RFC 4517
    public static final String PRESENTATION_ADDRESS_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.43";

    // RFC 4517, chap 3.3.29
    public static final String PRINTABLE_STRING_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.44";

    // RFC 2252, removed in RFC 4517
    public static final String SUBTREE_SPECIFICATION_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.45";

    // RFC 2252, removed in RFC 4517
    public static final String SUPPLIER_INFORMATION_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.46";

    // RFC 2252, removed in RFC 4517
    public static final String SUPPLIER_OR_CONSUMER_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.47";

    // RFC 2252, removed in RFC 4517
    public static final String SUPPLIER_AND_CONSUMER_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.48";

    // RFC 2252, removed in RFC 4517, reintroduced in RFC 4523, chap. 2.4
    public static final String SUPPORTED_ALGORITHM_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.49";

    // RFC 4517, chap 3.3.31
    public static final String TELEPHONE_NUMBER_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.50";

    // RFC 4517, chap 3.3.32
    public static final String TELETEX_TERMINAL_IDENTIFIER_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.51";

    // RFC 4517, chap 3.3.33
    public static final String TELEX_NUMBER_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.52";

    // RFC 4517, chap 3.3.34
    public static final String UTC_TIME_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.53";

    // RFC 4517, chap 3.3.18
    public static final String LDAP_SYNTAX_DESCRIPTION_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.54";

    // RFC 2252, removed in RFC 4517
    public static final String MODIFY_RIGHTS_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.55";

    // RFC 2252, removed in RFC 4517
    public static final String LDAP_SCHEMA_DEFINITION_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.56";

    // RFC 2252, removed in RFC 4517
    public static final String LDAP_SCHEMA_DESCRIPTION_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.57";

    // RFC 4517, chap 3.3.30
    public static final String SUBSTRING_ASSERTION_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.58";

    // From draft-ietf-pkix-ldap-v3-01.txt. Obsolete.
    public static final String ATTRIBUTE_CERTIFICATE_ASSERTION_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.59";

    //From RFC 4530, chap. 2.1
    public static final String UUID_SYNTAX = "1.3.6.1.1.16.1";

    // From http://www.openldap.org/faq/data/cache/1145.html
    public static final String CSN_SYNTAX = "1.3.6.1.4.1.4203.666.11.2.1";

    // From http://www.openldap.org/faq/data/cache/1145.html
    public static final String CSN_SID_SYNTAX = "1.3.6.1.4.1.4203.666.11.2.4";

    // ApacheDS
    public static final String JAVA_BYTE_SYNTAX = "1.3.6.1.4.1.18060.0.4.1.0.0";
    public static final String JAVA_CHAR_SYNTAX = "1.3.6.1.4.1.18060.0.4.1.0.1";
    public static final String JAVA_SHORT_SYNTAX = "1.3.6.1.4.1.18060.0.4.1.0.2";
    public static final String JAVA_LONG_SYNTAX = "1.3.6.1.4.1.18060.0.4.1.0.3";
    public static final String JAVA_INT_SYNTAX = "1.3.6.1.4.1.18060.0.4.1.0.4";

    // Comparator syntax
    public static final String COMPARATOR_SYNTAX = "1.3.6.1.4.1.18060.0.4.1.0.5";

    // Normalizer Syntax
    public static final String NORMALIZER_SYNTAX = "1.3.6.1.4.1.18060.0.4.1.0.6";

    // SyntaxChecker Syntax
    public static final String SYNTAX_CHECKER_SYNTAX = "1.3.6.1.4.1.18060.0.4.1.0.7";

    // SearchScope Syntax
    public static final String SEARCH_SCOPE_SYNTAX = "1.3.6.1.4.1.18060.0.4.1.0.10";

    // DerefAlias Syntax
    public static final String DEREF_ALIAS_SYNTAX = "1.3.6.1.4.1.18060.0.4.1.0.11";

    //-------------------------------------------------------------------------
    // ---- MatchingRules -----------------------------------------------------
    //-------------------------------------------------------------------------
    // caseExactIA5Match (RFC 4517, chap. 4.2.3)
    public static final String CASE_EXACT_IA5_MATCH_MR = "caseExactIA5Match";
    public static final String CASE_EXACT_IA5_MATCH_MR_OID = "1.3.6.1.4.1.1466.109.114.1";

    // caseIgnoreIA5Match (RFC 4517, chap. 4.2.7)
    public static final String CASE_IGNORE_IA5_MATCH_MR = "caseIgnoreIA5Match";
    public static final String CASE_IGNORE_IA5_MATCH_MR_OID = "1.3.6.1.4.1.1466.109.114.2";

    // caseIgnoreIA5SubstringsMatch (RFC 4517, chap. 4.2.8)
    public static final String CASE_IGNORE_IA5_SUBSTRINGS_MATCH_MR = "caseIgnoreIA5SubstringsMatch";
    public static final String CASE_IGNORE_IA5_SUBSTRINGS_MATCH_MR_OID = "1.3.6.1.4.1.1466.109.114.3";

    // objectIdentifierMatch (RFC 4517, chap. 4.2.26)
    public static final String OBJECT_IDENTIFIER_MATCH_MR = "objectIdentifierMatch";
    public static final String OBJECT_IDENTIFIER_MATCH_MR_OID = "2.5.13.0";

    // distinguishedNameMatch (RFC 4517, chap. 4.2.15)
    public static final String DISTINGUISHED_NAME_MATCH_MR = "distinguishedNameMatch";
    public static final String DISTINGUISHED_NAME_MATCH_MR_OID = "2.5.13.1";

    // caseIgnoreMatch (RFC 4517, chap. 3.3.19)
    public static final String CASE_IGNORE_MATCH_MR = "caseIgnoreMatch";
    public static final String CASE_IGNORE_MATCH_MR_OID = "2.5.13.2";

    // caseIgnoreOrderingMatch (RFC 4517, chap. 4.2.12)
    public static final String CASE_IGNORE_ORDERING_MATCH_MR = "caseIgnoreOrderingMatch";
    public static final String CASE_IGNORE_ORDERING_MATCH_MR_OID = "2.5.13.3";

    // caseIgnoreSubstringsMatch (RFC 4517, chap. 4.2.13)
    public static final String CASE_IGNORE_SUBSTRING_MATCH_MR = "caseIgnoreSubstringsMatch";
    public static final String CASE_IGNORE_SUBSTRING_MATCH_MR_OID = "2.5.13.4";

    // caseExactMatch (RFC 4517, chap. 4.2.4)
    public static final String CASE_EXACT_MATCH_MR = "caseExactMatch";
    public static final String CASE_EXACT_MATCH_MR_OID = "2.5.13.5";

    // caseExactOrderingMatch (RFC 4517, chap. 4.2.5)
    public static final String CASE_EXACT_ORDERING_MATCH_MR = "caseExactOrderingMatch";
    public static final String CASE_EXACT_ORDERING_MATCH_MR_OID = "2.5.13.6";

    // caseExactSubstringsMatch (RFC 4517, chap. 4.2.6)
    public static final String CASE_EXACT_SUBSTRING_MATCH_MR = "caseExactSubstringsMatch";
    public static final String CASE_EXACT_SUBSTRING_MATCH_MR_OID = "2.5.13.7";

    // numericStringMatch (RFC 4517, chap. 4.2.22)
    public static final String NUMERIC_STRING_MATCH_MR = "numericStringMatch";
    public static final String NUMERIC_STRING_MATCH_MR_OID = "2.5.13.8";

    // numericStringOrderingMatch (RFC 4517, chap. 4.2.23)
    public static final String NUMERIC_STRING_ORDERING_MATCH_MR = "numericStringOrderingMatch";
    public static final String NUMERIC_STRING_ORDERING_MATCH_MR_OID = "2.5.13.9";

    // numericStringSubstringsMatch (RFC 4517, chap. 4.2.24)
    public static final String NUMERIC_STRING_SUBSTRINGS_MATCH_MR = "numericStringSubstringsMatch";
    public static final String NUMERIC_STRING_SUBSTRINGS_MATCH_MR_OID = "2.5.13.10";

    // caseIgnoreListMatch (RFC 4517, chap. 4.2.9)
    public static final String CASE_IGNORE_LIST_MATCH_MR = "caseIgnoreListMatch";
    public static final String CASE_IGNORE_LIST_MATCH_MR_OID = "2.5.13.11";

    // caseIgnoreListSubstringsMatch (RFC 4517, chap. 4.2.10)
    public static final String CASE_IGNORE_LIST_SUBSTRINGS_MATCH_MR = "caseIgnoreListSubstringsMatch";
    public static final String CASE_IGNORE_LIST_SUBSTRINGS_MATCH_MR_OID = "2.5.13.12";

    // booleanMatch (RFC 4517, chap. 4.2.2)
    public static final String BOOLEAN_MATCH_MR = "booleanMatch";
    public static final String BOOLEAN_MATCH_MR_OID = "2.5.13.13";

    // integerMatch (RFC 4517, chap. 4.2.19)
    public static final String INTEGER_MATCH_MR = "integerMatch";
    public static final String INTEGER_MATCH_MR_OID = "2.5.13.14";

    // integerOrderingMatch (RFC 4517, chap. 4.2.20)
    public static final String INTEGER_ORDERING_MATCH_MR = "integerOrderingMatch";
    public static final String INTEGER_ORDERING_MATCH_MR_OID = "2.5.13.15";

    // bitStringMatch (RFC 4517, chap. 4.2.1)
    public static final String BIT_STRING_MATCH_MR = "bitStringMatch";
    public static final String BIT_STRING_MATCH_MR_OID = "2.5.13.16";

    // octetStringMatch (RFC 4517, chap. 4.2.27)
    public static final String OCTET_STRING_MATCH_MR = "octetStringMatch";
    public static final String OCTET_STRING_MATCH_MR_OID = "2.5.13.17";

    // octetStringMatch (RFC 4517, chap. 4.2.28)
    public static final String OCTET_STRING_ORDERING_MATCH_MR = "octetStringOrderingMatch";
    public static final String OCTET_STRING_ORDERING_MATCH_MR_OID = "2.5.13.18";

    // octetStringSubstringsMatch
    public static final String OCTET_STRING_SUBSTRINGS_MATCH_MR = "octetStringSubstringsMatch";
    public static final String OCTET_STRING_SUBSTRINGS_MATCH_MR_OID = "2.5.13.19";

    // telephoneNumberMatch (RFC 4517, chap. 4.2.29)
    public static final String TELEPHONE_NUMBER_MATCH_MR = "telephoneNumberMatch";
    public static final String TELEPHONE_NUMBER_MATCH_MR_OID = "2.5.13.20";

    // telephoneNumberMatch (RFC 4517, chap. 4.2.30)
    public static final String TELEPHONE_NUMBER_SUBSTRINGS_MATCH_MR = "telephoneNumberSubstringsMatch";
    public static final String TELEPHONE_NUMBER_SUBSTRINGS_MATCH_MR_OID = "2.5.13.21";

    // presentationAddressMatch Removed in RFC 4517
    public static final String PRESENTATION_ADDRESS_MATCH_MATCH_MR = "presentationAddressMatch";
    public static final String PRESENTATION_ADDRESS_MATCH_MATCH_MR_OID = "2.5.13.22";

    // uniqueMemberMatch (RFC 4517, chap. 4.2.31)
    public static final String UNIQUE_MEMBER_MATCH_MR = "uniqueMemberMatch";
    public static final String UNIQUE_MEMBER_MATCH_MR_OID = "2.5.13.23";

    // protocolInformationMatch Removed in RFC 4517
    public static final String PROTOCOL_INFORMATION_MATCH_MR = "protocolInformationMatch";
    public static final String PROTOCOL_INFORMATION_MATCH_MR_OID = "2.5.13.24";

    // "2.5.13.25" is not used ...
    // "2.5.13.26" is not used ...

    // generalizedTimeMatch (RFC 4517, chap. 4.2.16)
    public static final String GENERALIZED_TIME_MATCH_MR = "generalizedTimeMatch";
    public static final String GENERALIZED_TIME_MATCH_MR_OID = "2.5.13.27";

    // generalizedTimeOrderingMatch (RFC 4517, chap. 4.2.17)
    public static final String GENERALIZED_TIME_ORDERING_MATCH_MR = "generalizedTimeOrderingMatch";
    public static final String GENERALIZED_TIME_ORDERING_MATCH_MR_OID = "2.5.13.28";

    // integerFirstComponentMatch (RFC 4517, chap. 4.2.18)
    public static final String INTEGER_FIRST_COMPONENT_MATCH_MR = "integerFirstComponentMatch";
    public static final String INTEGER_FIRST_COMPONENT_MATCH_MR_OID = "2.5.13.29";

    // objectIdentifierFirstComponentMatch (RFC 4517, chap. 4.2.25)
    public static final String OBJECT_IDENTIFIER_FIRST_COMPONENT_MATCH_MR = "objectIdentifierFirstComponentMatch";
    public static final String OBJECT_IDENTIFIER_FIRST_COMPONENT_MATCH_MR_OID = "2.5.13.30";

    // directoryStringFirstComponentMatch (RFC 4517, chap. 4.2.14)
    public static final String DIRECTORY_STRING_FIRST_COMPONENT_MATCH_MR = "directoryStringFirstComponentMatch";
    public static final String DIRECTORY_STRING_FIRST_COMPONENT_MATCH_MR_OID = "2.5.13.31";

    // wordMatch (RFC 4517, chap. 4.2.32)
    public static final String WORD_MATCH_MR = "wordMatch";
    public static final String WORD_MATCH_MR_OID = "2.5.13.32";

    // keywordMatch (RFC 4517, chap. 4.2.21)
    public static final String KEYWORD_MATCH_MR = "keywordMatch";
    public static final String KEYWORD_MATCH_MR_OID = "2.5.13.33";

    // uuidMatch
    public static final String UUID_MATCH_MR = "uuidMatch";
    public static final String UUID_MATCH_MR_OID = "1.3.6.1.1.16.2";

    // uuidOrderingMatch
    public static final String UUID_ORDERING_MATCH_MR = "uuidOrderingMatch";
    public static final String UUID_ORDERING_MATCH_MR_OID = "1.3.6.1.1.16.3";

    // csnMatch
    public static final String CSN_MATCH_MR = "csnMatch";
    public static final String CSN_MATCH_MR_OID = "1.3.6.1.4.1.4203.666.11.2.2";

    // csnOrderingMatch
    public static final String CSN_ORDERING_MATCH_MR = "csnOrderingMatch";
    public static final String CSN_ORDERING_MATCH_MR_OID = "1.3.6.1.4.1.4203.666.11.2.3";

    // csnSidMatch
    public static final String CSN_SID_MATCH_MR = "csnSidMatch";
    public static final String CSN_SID_MATCH_MR_OID = "1.3.6.1.4.1.4203.666.11.2.5";

    // nameOrNumericIdMatch
    public static final String NAME_OR_NUMERIC_ID_MATCH = "nameOrNumericIdMatch";
    public static final String NAME_OR_NUMERIC_ID_MATCH_OID = "1.3.6.1.4.1.18060.0.4.0.1.0";

    // objectClassTypeMatch
    public static final String OBJECT_CLASS_TYPE_MATCH = "objectClassTypeMatch";
    public static final String OBJECT_CLASS_TYPE_MATCH_OID = "1.3.6.1.4.1.18060.0.4.0.1.1";

    // numericOidMatch
    public static final String NUMERIC_OID_MATCH = "numericOidMatch";
    public static final String NUMERIC_OID_MATCH_OID = "1.3.6.1.4.1.18060.0.4.0.1.2";

    // supDITStructureRuleMatch
    public static final String SUP_DIT_STRUCTURE_RULE_MATCH = "supDITStructureRuleMatch";
    public static final String SUP_DIT_STRUCTURE_RULE_MATCH_OID = "1.3.6.1.4.1.18060.0.4.0.1.3";

    // ruleIDMatch
    public static final String RULE_ID_MATCH = "ruleIDMatch";
    public static final String RULE_ID_MATCH_OID = "1.3.6.1.4.1.18060.0.4.0.1.4";

    // ExactDnAsStringMatch
    public static final String EXACT_DN_AS_STRING_MATCH_MR = "exactDnAsStringMatch";
    public static final String EXACT_DN_AS_STRING_MATCH_MR_OID = "1.3.6.1.4.1.18060.0.4.1.1.1";

    // BigIntegerMatch
    public static final String BIG_INTEGER_MATCH_MR = "bigIntegerMatch";
    public static final String BIG_INTEGER_MATCH_MR_OID = "1.3.6.1.4.1.18060.0.4.1.1.2";

    // JdbmStringMatch
    public static final String JDBM_STRING_MATCH_MR = "jdbmStringMatch";
    public static final String JDBM_STRING_MATCH_MR_OID = "1.3.6.1.4.1.18060.0.4.1.1.3";

    // ComparatorMatch
    public static final String COMPARATOR_MATCH_MR = "comparatorMatch";
    public static final String COMPARATOR_MATCH_MR_OID = "1.3.6.1.4.1.18060.0.4.1.1.5";

    // NormalizerMatch
    public static final String NORMALIZER_MATCH_MR = "normalizerMatch";
    public static final String NORMALIZER_MATCH_MR_OID = "1.3.6.1.4.1.18060.0.4.1.1.6";

    // SyntaxCheckerMatch
    public static final String SYNTAX_CHECKER_MATCH_MR = "syntaxCheckerMatch";
    public static final String SYNTAX_CHECKER_MATCH_MR_OID = "1.3.6.1.4.1.18060.0.4.1.1.7";

    // ---- Features ----------------------------------------------------------
    public static final String FEATURE_ALL_OPERATIONAL_ATTRIBUTES = "1.3.6.1.4.1.4203.1.5.1";

    // ----Administrative roles -----------------------------------------------
    // AutonomousArea
    public static final String AUTONOMOUS_AREA = "autonomousArea";
    public static final String AUTONOMOUS_AREA_OID = "2.5.23.1";

    // AccessControlSpecificArea
    public static final String ACCESS_CONTROL_SPECIFIC_AREA = "accessControlSpecificArea";
    public static final String ACCESS_CONTROL_SPECIFIC_AREA_OID = "2.5.23.2";

    // AccessControlInnerArea
    public static final String ACCESS_CONTROL_INNER_AREA = "accessControlInnerArea";
    public static final String ACCESS_CONTROL_INNER_AREA_OID = "2.5.23.3";

    // SubSchemaAdminSpecificArea
    public static final String SUB_SCHEMA_ADMIN_SPECIFIC_AREA = "subSchemaSpecificArea";
    public static final String SUB_SCHEMA_ADMIN_SPECIFIC_AREA_OID = "2.5.23.4";

    // CollectiveAttributeSpecificArea
    public static final String COLLECTIVE_ATTRIBUTE_SPECIFIC_AREA = "collectiveAttributeSpecificArea";
    public static final String COLLECTIVE_ATTRIBUTE_SPECIFIC_AREA_OID = "2.5.23.5";

    // CollectiveAttributeInnerArea
    public static final String COLLECTIVE_ATTRIBUTE_INNER_AREA = "collectiveAttributeInnerArea";
    public static final String COLLECTIVE_ATTRIBUTE_INNER_AREA_OID = "2.5.23.6";

    // TriggerExecutionSpecificArea
    public static final String TRIGGER_EXECUTION_SPECIFIC_AREA = "triggerExecutionSpecificArea";
    public static final String TRIGGER_EXECUTION_SPECIFIC_AREA_OID = "1.3.6.1.4.1.18060.0.4.1.6.1";

    // TriggerExecutionInnerArea
    public static final String TRIGGER_EXECUTION_INNER_AREA = "triggerExecutionInnerArea";
    public static final String TRIGGER_EXECUTION_INNER_AREA_OID = "1.3.6.1.4.1.18060.0.4.1.6.2";
}
