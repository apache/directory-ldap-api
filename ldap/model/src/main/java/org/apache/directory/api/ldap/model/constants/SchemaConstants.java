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
 * Final reference -&gt; class shouldn't be extended
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
    // We list here all the ObjectClasses from schemas :
    // o apachemeta
    // o autofs
    // o core
    // o corba
    // o cosine
    // o inetorgperson
    // o nis
    // o pwdpolicy
    // o system
    //
    // The collectiveAttribute schema has no ObjectClass.
    // 
    // We don't list here the complete list of ObjectClasses for the following
    // schemas :
    // o adsconfig
    // o apache
    // o apachedns
    // o dhcp
    // o java
    // o krb5kdc
    // o mozilla
    // o samba
    //-------------------------------------------------------------------------
    // o apachemeta
    //-------------------------------------------------------------------------
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

    //-------------------------------------------------------------------------
    // autofs
    //-------------------------------------------------------------------------
    // AutomountMap
    public static final String AUTOMOUNT_MAP_OC = "automountMap";
    public static final String AUTOMOUNT_MAP_OC_OID = "1.3.6.1.4.1.2312.4.2.2";

    // Automount
    public static final String AUTOMOUNT_OC = "automount";
    public static final String AUTOMOUNT_OC_OID = "1.3.6.1.4.1.2312.4.2.3";

    //-------------------------------------------------------------------------
    // corba
    //-------------------------------------------------------------------------
    // CorbaObject
    public static final String CORBA_OBJECT_OC = "corbaObject";
    public static final String CORBA_OBJECT_OC_OID = "1.3.6.1.4.1.42.2.27.4.2.9";

    // CorbaContainer
    public static final String CORBA_CONTAINER_OC = "corbaContainer";
    public static final String CORBA_CONTAINER_OC_OID = "1.3.6.1.4.1.42.2.27.4.2.10";

    // CorbaReference
    public static final String CORBA_REFERENCE_OC = "corbaReference";
    public static final String CORBA_REFERENCE_OC_OID = "1.3.6.1.4.1.42.2.27.4.2.11";

    //-------------------------------------------------------------------------
    // core
    //-------------------------------------------------------------------------
    // SimpleSecurityObject
    public static final String SIMPLE_SECURITY_OBJECT_OC = "simpleSecurityObject";
    public static final String SIMPLE_SECURITY_OBJECT_OC_OID = "0.9.2342.19200300.100.4.19";

    // UidObject
    public static final String UID_OBJECT_OC = "uidObject";
    public static final String UID_OBJECT_OC_OID = "1.3.6.1.1.3.1";

    // LabeledURIObject
    public static final String LABELED_URI_OBJECT_OC = "labeledURIObject";
    public static final String LABELED_URI_OBJECT_OC_OID = "1.3.6.1.4.1.250.3.15";

    // DcObject
    public static final String DC_OBJECT_OC = "dcObject";
    public static final String DC_OBJECT_OC_OID = "1.3.6.1.4.1.1466.344";

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

    // ApplicationProcess
    public static final String APPLICATION_PROCESS_OC = "applicationProcess";
    public static final String APPLICATION_PROCESS_OC_OID = "2.5.6.11";

    // ApplicationEntity
    public static final String APPLICATION_ENTITY_OC = "applicationEntity";
    public static final String APPLICATION_ENTITY_OC_OID = "2.5.6.12";

    // DSA
    public static final String DSA_OC = "dSA";
    public static final String DSA_OC_OID = "2.5.6.13";

    // Device
    public static final String DEVICE_OC = "device";
    public static final String DEVICE_OC_OID = "2.5.6.14";

    // StrongAuthenticationUser
    public static final String STRONG_AUTHENTICATION_USER_OC = "strongAuthenticationUser";
    public static final String STRONG_AUTHENTICATION_USER_OC_OID = "2.5.6.15";

    // CertificationAuthority
    public static final String CERTIFICATION_AUTHORITY_OC = "certificationAuthority";
    public static final String CERTIFICATION_AUTHORITY_OC_OID = "2.5.6.16";

    // CertificationAuthority-V2
    public static final String CERTIFICATION_AUTHORITY_V2_OC = "certificationAuthority-V2";
    public static final String CERTIFICATION_AUTHORITY_V2_OC_OID = "2.5.6.16.2";

    // GroupOfUniqueNames
    public static final String GROUP_OF_UNIQUE_NAMES_OC = "groupOfUniqueNames";
    public static final String GROUP_OF_UNIQUE_NAMES_OC_OID = "2.5.6.17";

    // UserSecurityInformation
    public static final String USER_SECURITY_INFORMATION_OC = "userSecurityInformation";
    public static final String USER_SECURITY_INFORMATION_OC_OID = "2.5.6.18";

    // CRLDistributionPoint
    public static final String CRL_DISTRIBUTION_POINT_OC = "cRLDistributionPoint";
    public static final String CRL_DISTRIBUTION_POINT_OC_OID = "2.5.6.19";

    // Dmd
    public static final String DMD_OC = "dmd";
    public static final String DMD_OC_OID = "2.5.6.20";

    // PkiUser
    public static final String PKI_USER_OC = "pkiUser";
    public static final String PKI_USER_OC_OID = "2.5.6.21";

    // PkiCA
    public static final String PKI_CA_OC = "pkiCA";
    public static final String PKI_CA_OC_OID = "2.5.6.22";

    // DeltaCRL
    public static final String DELTA_CRL_OC = "deltaCRL";
    public static final String DELTA_CRL_OC_OID = "2.5.6.23";

    //-------------------------------------------------------------------------
    // cosine
    //-------------------------------------------------------------------------
    // PilotPerson
    public static final String PILOT_PERSON_OC = "pilotPerson";
    public static final String NEW_PILOT_PERSON_OC = "newPilotPerson";
    public static final String PILOT_PERSON_OC_OID = "0.9.2342.19200300.100.4.4";

    // Account
    public static final String ACCOUNT_OC = "account";
    public static final String ACCOUNT_OC_OID = "0.9.2342.19200300.100.4.5";

    // Document
    public static final String DOCUMENT_OC = "document";
    public static final String DOCUMENT_OC_OID = "0.9.2342.19200300.100.4.6";

    // Room
    public static final String ROOM_OC = "room";
    public static final String ROOM_OC_OID = "0.9.2342.19200300.100.4.7";

    // DocumentSeries
    public static final String DOCUMENT_SERIES_OC = "documentSeries";
    public static final String DOCUMENT_SERIES_OC_OID = "0.9.2342.19200300.100.4.9";

    // Domain
    public static final String DOMAIN_OC = "domain";
    public static final String DOMAIN_OC_OID = "0.9.2342.19200300.100.4.13";

    // RFC822LocalPart
    public static final String RFC822_LOCAL_PART_OC = "RFC822LocalPart";
    public static final String RFC822_LOCAL_PART_OC_OID = "0.9.2342.19200300.100.4.14";

    // DNSDomain
    public static final String DNS_DOMAIN_OC = "dNSdomain";
    public static final String DNS_DOMAIN_OC_OID = "0.9.2342.19200300.100.4.15";

    // DomainRelatedObject
    public static final String DOMAIN_RELATED_OBJECT_OC = "domainRelatedObject";
    public static final String DOMAIN_RELATED_OBJECT_OC_OID = "0.9.2342.19200300.100.4.17";

    // FriendlyCountry
    public static final String FRIENDLY_COUNTRY_OC = "friendlyCountry";
    public static final String FRIENDLY_COUNTRY_OC_OID = "0.9.2342.19200300.100.4.18";

    // PilotOrganization
    public static final String PILOT_ORGANIZATION_OC = "pilotOrganization";
    public static final String PILOT_ORGANIZATION_OC_OID = "0.9.2342.19200300.100.4.20";

    // PilotDSA
    public static final String PILOT_DSA_OC = "pilotDSA";
    public static final String PILOT_DSA_OC_OID = "0.9.2342.19200300.100.4.21";

    // QualityLabelledData
    public static final String QUALITY_LABELLED_DATA_OC = "qualityLabelledData";
    public static final String QUALITY_LABELLED_DATA_OC_OID = "0.9.2342.19200300.100.4.22";

    //-------------------------------------------------------------------------
    // inetorgperson
    //-------------------------------------------------------------------------
    // InetOrgPerson
    public static final String INET_ORG_PERSON_OC = "inetOrgPerson";
    public static final String INET_ORG_PERSON_OC_OID = "2.16.840.1.113730.3.2.2";

    //-------------------------------------------------------------------------
    // nis
    //-------------------------------------------------------------------------
    // PosixAccount
    public static final String POSIX_ACCOUNT_OC = "posicAccount";
    public static final String POSIX_ACCOUNT_OC_OID = "1.3.6.1.1.1.2.0";

    // ShadowAccount
    public static final String SHADOW_ACCOUNT_OC = "shadowAccount";
    public static final String SHADOW_ACCOUNT_OC_OID = "1.3.6.1.1.1.2.1";

    // PosixGroup
    public static final String POSIX_GROUP_OC = "posixGroup";
    public static final String POSIX_GROUP_OC_OID = "1.3.6.1.1.1.2.2";

    // IpService
    public static final String IP_SERVICE_OC = "ipService";
    public static final String IP_SERVICE_OC_OID = "1.3.6.1.1.1.2.3";

    // IpProtocol
    public static final String IP_PROTOCOL_OC = "ipProtocol";
    public static final String IP_PROTOCOL_OC_OID = "1.3.6.1.1.1.2.4";

    // OncRpc
    public static final String ONC_RPC_OC = "oncRpc";
    public static final String ONC_RPC_OC_OID = "1.3.6.1.1.1.2.5";

    // IpHost
    public static final String IP_HOST_OC = "ipHost";
    public static final String IP_HOST_OC_OID = "1.3.6.1.1.1.2.6";

    // IpNetwork
    public static final String IP_NETWORK_OC = "ipNetwork";
    public static final String IP_NETWORK_OC_OID = "1.3.6.1.1.1.2.7";

    // NisNetgroup
    public static final String NIS_NETGROUP_OC = "nisNetgroup";
    public static final String NIS_NETGROUP_OC_OID = "1.3.6.1.1.1.2.8";

    // NisMap
    public static final String NIS_MAP_OC = "nisMap";
    public static final String NIS_MAP_OC_OID = "1.3.6.1.1.1.2.9";

    // NisObject
    public static final String NIS_OBJECT_OC = "nisObject";
    public static final String NIS_OBJECT_OC_OID = "1.3.6.1.1.1.2.10";

    // Ieee802Device
    public static final String IEEE_802_DEVICE_OC = "ieee802Device";
    public static final String IEEE_802_DEVICE_OC_OID = "1.3.6.1.1.1.2.11";

    // BootableDevice
    public static final String BOOTABLE_DEVICE_OC = "bootableDevice";
    public static final String BOOTABLE_DEVICE_OC_OID = "1.3.6.1.1.1.2.12";

    //-------------------------------------------------------------------------
    // pwdpolicy
    //-------------------------------------------------------------------------
    // PwdPolicy
    public static final String PWD_POLICY_OC = "pwdPolicy";
    public static final String PWD_POLICY_OC_OID = "1.3.6.1.4.1.42.2.27.8.2.1";

    //-------------------------------------------------------------------------
    // system
    //-------------------------------------------------------------------------
    // DynamicObject
    public static final String DYNAMIC_OBJECT_OC = "dynamicObject";
    public static final String DYNAMIC_OBJECT_OC_OID = "1.3.6.1.4.1.1466.101.119.2";

    // ExtensibleObject
    public static final String EXTENSIBLE_OBJECT_OC = "extensibleObject";
    public static final String EXTENSIBLE_OBJECT_OC_OID = "1.3.6.1.4.1.1466.101.120.111";

    // LDAProotDSE, OpenLDAProotDSE
    public static final String LDAP_ROOT_DSE_OC = "LDAProotDSE";
    public static final String OPEN_LDAP_ROOT_DSE_OC = "OpenLDAProotDSE";
    public static final String LDAP_ROOT_DSE_OC_OID = "1.3.6.1.4.1.4203.1.4.1";

    // Top
    public static final String TOP_OC = "top";
    public static final String TOP_OC_OID = "2.5.6.0";

    // Alias
    public static final String ALIAS_OC = "alias";
    public static final String ALIAS_OC_OID = "2.5.6.1";

    // Subentry
    public static final String SUBENTRY_OC = "subentry";
    public static final String SUBENTRY_OC_OID = "2.5.17.0";

    // CollectiveAttributeSubentry
    public static final String COLLECTIVE_ATTRIBUTE_SUBENTRY_OC = "collectiveAttributeSubentry";
    public static final String COLLECTIVE_ATTRIBUTE_SUBENTRY_OC_OID = "2.5.17.2";

    // Subschema
    public static final String SUBSCHEMA_OC = "subschema";
    public static final String SUBSCHEMA_OC_OID = "2.5.20.1";

    // Referral
    public static final String REFERRAL_OC = "referral";
    public static final String REFERRAL_OC_OID = "2.16.840.1.113730.3.2.6";

    //-------------------------------------------------------------------------
    // Other schema ObjectClasses
    //-------------------------------------------------------------------------
    // Krb5Principal
    public static final String KRB5_PRINCIPAL_OC = "krb5Principal";
    public static final String KRB5_PRINCIPAL_OC_OID = "1.3.6.1.4.1.5322.10.2.1";

    // AccessControlSubentry
    public static final String ACCESS_CONTROL_SUBENTRY_OC = "accessControlSubentry";
    public static final String ACCESS_CONTROL_SUBENTRY_OC_OID = "2.5.17.1";

    // TriggerExecutionSubentry
    public static final String TRIGGER_EXECUTION_SUBENTRY_OC = "triggerExecutionSubentry";
    public static final String TRIGGER_EXECUTION_SUBENTRY_OC_OID = "1.3.6.1.4.1.18060.0.4.1.2.28";

    //-------------------------------------------------------------------------
    // AttributeTypes for standard schemas are listed below. We cover the 
    // following schemas :
    // o apachemeta
    // o autofs
    // o collective
    // o corba
    // o core
    // o cosine
    // o inetorgperson
    // o nis
    // o passwordpolicy
    // o system
    //
    // We don't cover the following schemas :
    // o adsconfig
    // o apache
    // o apachedns
    // o dhcp
    // o java
    // o krb5kdc
    // o mozilla
    // o samba
    //-------------------------------------------------------------------------
    // apachemeta AttributeTypes
    //-------------------------------------------------------------------------
    // M-oid AT
    public static final String M_OID_AT = "m-oid";
    public static final String M_OID_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.1";

    // M-name AT
    public static final String M_NAME_AT = "m-name";
    public static final String M_NAME_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.2";

    // M-description AT
    public static final String M_DESCRIPTION_AT = "m-description";
    public static final String M_DESCRIPTION_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.3";

    // M-obsolete AT
    public static final String M_OBSOLETE_AT = "m-obsolete";
    public static final String M_OBSOLETE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.4";

    // M-supObjectClass AT
    public static final String M_SUP_OBJECT_CLASS_AT = "m-supObjectClass";
    public static final String M_SUP_OBJECT_CLASS_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.5";

    // M-must AT
    public static final String M_MUST_AT = "m-must";
    public static final String M_MUST_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.6";

    // M-may AT
    public static final String M_MAY_AT = "m-may";
    public static final String M_MAY_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.7";

    // M-typeObjectClass AT
    public static final String M_TYPE_OBJECT_CLASS_AT = "m-typeObjectClass";
    public static final String M_TYPE_OBJECT_CLASS_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.8";

    // M-supAttributeType AT
    public static final String M_SUP_ATTRIBUTE_TYPE_AT = "m-supAttributeType";
    public static final String M_SUP_ATTRIBUTE_TYPE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.10";

    // M-equality AT
    public static final String M_EQUALITY_AT = "m-equality";
    public static final String M_EQUALITY_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.11";

    // M-ordering AT
    public static final String M_ORDERING_AT = "m-ordering";
    public static final String M_ORDERING_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.12";

    // M-substr AT
    public static final String M_SUBSTR_AT = "m-substr";
    public static final String M_SUBSTR_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.13";

    // M-syntax AT
    public static final String M_SYNTAX_AT = "m-syntax";
    public static final String M_SYNTAX_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.14";

    // M-singleValue AT
    public static final String M_SINGLE_VALUE_AT = "m-singleValue";
    public static final String M_SINGLE_VALUE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.15";

    // M-collective AT
    public static final String M_COLLECTIVE_AT = "m-collective";
    public static final String M_COLLECTIVE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.16";

    // M-noUserModification AT
    public static final String M_NO_USER_MODIFICATION_AT = "m-noUserModification";
    public static final String M_NO_USER_MODIFICATION_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.17";

    // M-usage AT
    public static final String M_USAGE_AT = "m-usage";
    public static final String M_USAGE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.18";

    // M-ruleId AT
    public static final String M_RULEID_AT = "m-ruleId";
    public static final String M_RULEID_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.20";

    // M-form AT
    public static final String M_FORM_AT = "m-form";
    public static final String M_FORM_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.21";

    // M-supDITStructureRule AT
    public static final String M_SUP_DIT_STRUCTURE_RULE_AT = "m-supDITStructureRule";
    public static final String M_SUP_DIT_STRUCTURE_RULE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.22";

    // M-oc AT
    public static final String M_OC_AT = "m-oc";
    public static final String M_OC_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.24";

    // M-aux AT
    public static final String M_AUX_AT = "m-aux";
    public static final String M_AUX_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.26";

    // M-not AT
    public static final String M_NOT_AT = "m-not";
    public static final String M_NOT_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.27";

    // M-applies AT
    public static final String M_APPLIES_AT = "m-applies";
    public static final String M_APPLIES_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.29";

    // M-matchingRuleSyntax AT
    public static final String M_MATCHING_RULE_SYNTAX_AT = "m-matchingRuleSyntax";
    public static final String M_MATCHING_RULE_SYNTAX_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.31";

    // M-fqcn AT
    public static final String M_FQCN_AT = "m-fqcn";
    public static final String M_FQCN_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.32";

    // M-bytecode AT
    public static final String M_BYTECODE_AT = "m-bytecode";
    public static final String M_BYTECODE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.33";

    // x-not-human-readable AT
    public static final String X_NOT_HUMAN_READABLE_AT = "x-not-human-readable";
    public static final String X_NOT_HUMAN_READABLE_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.34";

    // x-schema AT
    public static final String X_SCHEMA_AT = "x-schema";
    public static final String X_SCHEMA_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.35";

    // x-read-only AT
    public static final String X_READ_ONLY_AT = "x-read-only";
    public static final String X_READ_ONLY_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.36";

    // M-disabled AT
    public static final String M_DISABLED_AT = "m-disabled";
    public static final String M_DISABLED_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.37";

    // M-dependencies AT
    public static final String M_DEPENDENCIES_AT = "m-dependencies";
    public static final String M_DEPENDENCIES_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.38";

    // M-length AT
    public static final String M_LENGTH_AT = "m-length";
    public static final String M_LENGTH_AT_OID = "1.3.6.1.4.1.18060.0.4.0.2.39";

    //-------------------------------------------------------------------------
    // autofs AttributeTypes
    //-------------------------------------------------------------------------
    // AutomountInformation
    public static final String AUTOMOUNT_INFORMATION_AT = "automountInformation";
    public static final String AUTOMOUNT_INFORMATION_AT_OID = "1.3.6.1.4.1.2312.4.1.2";

    //-------------------------------------------------------------------------
    // collective AttributeTypes
    //-------------------------------------------------------------------------
    // C-l
    public static final String C_L_AT = "c-l";
    public static final String C_L_AT_OID = "2.5.4.7.1";

    // C-st
    public static final String C_ST_AT = "c-st";
    public static final String C_ST_AT_OID = "2.5.4.8.1";

    // C-street
    public static final String C_STREET_AT = "c-street";
    public static final String C_STREET_AT_OID = "2.5.4.9.1";

    // C-o
    public static final String C_O_AT = "c-o";
    public static final String C_O_AT_OID = "2.5.4.10.1";

    // C-ou
    public static final String C_OU_AT = "c-ou";
    public static final String C_OU_AT_OID = "2.5.4.11.1";

    // C-postalAddress
    public static final String C_POSTAL_ADDRESS_AT = "c-postalAddress";
    public static final String C_POSTAL_ADDRESS_AT_OID = "2.5.4.16.1";

    // C-postalCode
    public static final String C_POSTALCODE_AT = "c-postalCode";
    public static final String C_POSTALCODE_AT_OID = "2.5.4.17.1";

    // C-postOfficeBox
    public static final String C_POSTOFFICEBOX_AT = "c-postOfficeBox";
    public static final String C_POSTOFFICEBOX_AT_OID = "2.5.4.18.1";

    // C-physicalDeliveryOfficeName
    public static final String C_PHYSICAL_DELIVERY_OFFICE_NAME_AT = "c-physicalDeliveryOfficeName";
    public static final String C_PHYSICAL_DELIVERY_OFFICE_NAME_AT_OID = "2.5.4.19.1";

    // C-telephoneNumber
    public static final String C_TELEPHONE_NUMBER_AT = "c-telephoneNumber";
    public static final String C_TELEPHONE_NUMBER_AT_OID = "2.5.4.20.1";

    // C-telexNumber
    public static final String C_TELEX_NUMBER_AT = "c-telexNumber";
    public static final String C_TELEX_NUMBER_AT_OID = "2.5.4.21.1";

    // C-fax
    public static final String C_FACSIMILE_TELEPHONE_NUMBER_AT = "c-facsimileTelephoneNumber";
    public static final String C_FACSIMILE_TELEPHONE_NUMBER_AT_OID = "2.5.4.23.1";

    // C-internationaliSDNNumber
    public static final String C_INTERNATIONAL_ISDN_NUMBER_AT = "c-internationaliSDNNumber";
    public static final String C_INTERNATIONAL_ISDN_NUMBER_AT_OID = "2.5.4.25.1";

    //-------------------------------------------------------------------------
    // corba AttributeTypes
    //-------------------------------------------------------------------------
    // CorbaIor AT
    public static final String CORBA_IOR_AT = "corbaIor";
    public static final String CORBA_IOR_AT_OID = "1.3.6.1.4.1.42.2.27.4.1.14";

    // CorbaRepositoryId AT
    public static final String CORBA_REPOSITORY_ID_AT = "corbaRepositoryId";
    public static final String CORBA_REPOSITORY_ID_AT_OID = "1.3.6.1.4.1.42.2.27.4.1.15";

    //-------------------------------------------------------------------------
    // core AttributeTypes
    //-------------------------------------------------------------------------
    // Uid
    public static final String UID_AT = "uid";
    public static final String USER_ID_AT = "userid";
    public static final String UID_AT_OID = "0.9.2342.19200300.100.1.1";

    // Mail 
    public static final String MAIL_AT = "mail";
    public static final String RFC822_MAILBOX_AT = "rfc822Mailbox";
    public static final String MAIL_AT_OID = "0.9.2342.19200300.100.1.3";

    // DomainComponent
    public static final String DC_AT = "dc";
    public static final String DOMAIN_COMPONENT_AT = "domainComponent";
    public static final String DOMAIN_COMPONENT_AT_OID = "0.9.2342.19200300.100.1.25";

    // AssociatedDomain
    public static final String ASSOCIATED_DOMAIN_AT = "associatedDomain";
    public static final String ASSOCIATED_DOMAIN_AT_OID = "0.9.2342.19200300.100.1.37";

    // Emails
    public static final String EMAIL_AT = "email";
    public static final String EMAIL_ADDRESS_AT = "emailAddress";
    public static final String PKCS9EMAIL_AT = "pkcs9email";
    public static final String EMAIL_AT_OID = "1.2.840.113549.1.9.1";

    // UidObject
    public static final String UID_OBJECT_AT = "uidObject";
    public static final String UID_OBJECT_AT_OID = "1.3.6.1.1.3.1";

    // knowledgeInformation
    public static final String KNOWLEDGE_INFORMATION_AT = "knowledgeInformation";
    public static final String KNOWLEDGE_INFORMATION_AT_OID = "2.5.4.2";

    // Sn
    public static final String SN_AT = "sn";
    public static final String SURNAME_AT = "surname";
    public static final String SN_AT_OID = "2.5.4.4";

    // SerialNumber
    public static final String SERIAL_NUMBER_AT = "serialNumber";
    public static final String SERIAL_NUMBER_AT_OID = "2.5.4.5";

    // C, CountryName
    public static final String C_AT = "c";
    public static final String COUNTRY_NAME_AT = "countryName";
    public static final String C_AT_OID = "2.5.4.6";

    // L, LocalityName
    public static final String L_AT = "l";
    public static final String LOCALITY_NAME_AT = "localityName";
    public static final String L_AT_OID = "2.5.4.7";
    public static final String LOCALITY_NAME_AT_OID = "2.5.4.7";

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
    public static final String ORGANIZATION_NAME_AT_OID = "2.5.4.10";

    // Ou
    public static final String OU_AT = "ou";
    public static final String ORGANIZATIONAL_UNIT_NAME_AT = "organizationalUnitName";
    public static final String OU_AT_OID = "2.5.4.11";
    public static final String ORGANIZATIONAL_UNIT_NAME_AT_OID = "2.5.4.11";

    // Title
    public static final String TITLE_AT = "title";
    public static final String TITLE_AT_OID = "2.5.4.12";

    // Description
    public static final String DESCRIPTION_AT = "description";
    public static final String DESCRIPTION_AT_OID = "2.5.4.13";

    // SearchGuide
    public static final String SEARCHGUIDE_AT = "searchguide";
    public static final String SEARCHGUIDE_AT_OID = "2.5.4.14";

    // BusinessCategory
    public static final String BUSINESS_CATEGORY_AT = "businessCategory";
    public static final String BUSINESS_CATEGORY_AT_OID = "2.5.4.15";

    // PostalAddress
    public static final String POSTAL_ADDRESS_AT = "postalAddress";
    public static final String POSTAL_ADDRESS_AT_OID = "2.5.4.16";

    // PostalCode
    public static final String POSTALCODE_AT = "postalCode";
    public static final String POSTALCODE_AT_OID = "2.5.4.17";

    // PostOfficeBox
    public static final String POSTOFFICEBOX_AT = "postOfficeBox";
    public static final String POSTOFFICEBOX_AT_OID = "2.5.4.18";

    // PhysicalDeliveryOfficeName
    public static final String PHYSICAL_DELIVERY_OFFICE_NAME_AT = "physicalDeliveryOfficeName";
    public static final String PHYSICAL_DELIVERY_OFFICE_NAME_AT_OID = "2.5.4.19";

    // TelephoneNumber
    public static final String TELEPHONE_NUMBER_AT = "telephoneNumber";
    public static final String TELEPHONE_NUMBER_AT_OID = "2.5.4.20";

    // TelexNumber
    public static final String TELEX_NUMBER_AT = "telexNumber";
    public static final String TELEX_NUMBER_AT_OID = "2.5.4.21";

    // TeletexTerminalIdentifier
    public static final String TELETEX_TERMINAL_IDENTIFIER_AT = "teletexTerminalIdentifier";
    public static final String TELETEX_TERMINAL_IDENTIFIER_AT_OID = "2.5.4.22";

    // Fax
    public static final String FAX_AT = "fax";
    public static final String FACSIMILE_TELEPHONE_NUMBER_AT = "facsimileTelephoneNumber";
    public static final String FACSIMILE_TELEPHONE_NUMBER_AT_OID = "2.5.4.23";

    // X121Address
    public static final String X12_1ADDRESS_AT = "x121Address";
    public static final String X121_ADDRESS_AT_OID = "2.5.4.24";

    // InternationaliSDNNumber
    public static final String INTERNATIONAL_ISDN_NUMBER_AT = "internationaliSDNNumber";
    public static final String INTERNATIONAL_ISDN_NUMBER_AT_OID = "2.5.4.25";

    // RegisteredAddress
    public static final String REGISTERED_ADDRESS_AT = "registeredAddress";
    public static final String REGISTERED_ADDRESS_AT_OID = "2.5.4.26";

    // DestinationIndicator
    public static final String DESTINATION_INDICATOR_AT = "destinationIndicator";
    public static final String DESTINATION_INDICATOR_AT_OID = "2.5.4.27";

    // PreferredDeliveryMethod
    public static final String PREFERRED_DELIVERY_METHOD_AT = "preferredDeliveryMethod";
    public static final String PREFERRED_DELIVERY_METHOD_AT_OID = "2.5.4.28";

    // PresentationAddress
    public static final String PRESENTATION_ADDRESS_AT = "presentationAddress";
    public static final String PRESENTATION_ADDRESS_AT_OID = "2.5.4.29";

    // SupportedApplicationContext
    public static final String SUPPORTED_APPLICATION_CONTEXT_AT = "supportedApplicationContext";
    public static final String SUPPORTED_APPLICATION_CONTEXT_AT_OID = "2.5.4.30";

    // Member
    public static final String MEMBER_AT = "member";
    public static final String MEMBER_AT_OID = "2.5.4.31";

    // Owner
    public static final String OWNER_AT = "owner";
    public static final String OWNER_AT_OID = "2.5.4.32";

    // RoleOccupant
    public static final String ROLE_OCCUPANT_AT = "roleOccupant";
    public static final String ROLE_OCCUPANT_AT_OID = "2.5.4.33";

    // SeeAlso
    public static final String SEE_ALSO_AT = "seeAlso";
    public static final String SEE_ALSO_AT_OID = "2.5.4.34";

    // UserCertificate
    public static final String USER_CERTIFICATE_AT = "userCertificate";
    public static final String USER_CERTIFICATE_AT_OID = "2.5.4.36";

    // CACertificate
    public static final String CA_CERTIFICATE_AT = "cACertificate";
    public static final String CA_CERTIFICATE_AT_OID = "2.5.4.37";

    // AuthorityRevocationList
    public static final String AUTHORITY_REVOCATION_LIST_AT = "authorityRevocationList";
    public static final String AUTHORITY_REVOCATION_LIST_AT_OID = "2.5.4.38";

    // CertificateRevocationList
    public static final String CERTIFICATE_REVOCATION_LIST_AT = "certificateRevocationList";
    public static final String CERTIFICATE_REVOCATION_LIST_AT_OID = "2.5.4.39";

    // CrossCertificatePair
    public static final String CROSS_CERTIFICATE_PAIR_AT = "crossCertificatePair";
    public static final String CROSS_CERTIFICATE_PAIR_AT_OID = "2.5.4.40";

    // Gn
    public static final String GN_AT = "gn";
    public static final String GIVENNAME_AT = "givenName";
    public static final String GN_AT_OID = "2.5.4.42";
    public static final String GIVENNAME_AT_OID = "2.5.4.42";

    // Initials
    public static final String INITIALS_AT = "initials";
    public static final String INITIALS_AT_OID = "2.5.4.43";

    // GenerationQualifier
    public static final String GENERATION_QUALIFIER_AT = "generationQualifier";
    public static final String GENERATION_QUALIFIER_AT_OID = "2.5.4.44";

    // X500UniqueIdentifier
    public static final String X500_UNIQUE_IDENTIFIER_AT = "x500UniqueIdentifier";
    public static final String X500_UNIQUE_IDENTIFIER_AT_OID = "2.5.4.45";

    // DnQualifier
    public static final String DN_QUALIFIER_AT = "dnQualifier";
    public static final String DN_QUALIFIER_AT_OID = "2.5.4.46";

    // EnhancedSearchGuide
    public static final String ENHANCED_SEARCH_GUIDE_AT = "enhancedSearchGuide";
    public static final String ENHANCED_SEARCH_GUIDE_AT_OID = "2.5.4.47";

    // ProtocolInformation
    public static final String PROTOCOL_INFORMATION_AT = "protocolInformation";
    public static final String PROTOCOL_INFORMATION_AT_OID = "2.5.4.48";

    // DistinguishedName
    public static final String DISTINGUISHED_NAME_AT = "distinguishedName";
    public static final String DISTINGUISHED_NAME_AT_OID = "2.5.4.49";

    // UniqueMember
    public static final String UNIQUE_MEMBER_AT = "uniqueMember";
    public static final String UNIQUE_MEMBER_AT_OID = "2.5.4.50";

    // HouseIdentifier
    public static final String HOUSE_IDENTIFIER_AT = "houseIdentifier";
    public static final String HOUSE_IDENTIFIER_AT_OID = "2.5.4.51";

    // SupportedAlgorithms
    public static final String SUPPORTED_ALGORITHMS_AT = "supportedAlgorithms";
    public static final String SUPPORTED_ALGORITHMS_AT_OID = "2.5.4.52";

    // DeltaRevocationList
    public static final String DELTA_REVOCATION_LIST_AT = "deltaRevocationList";
    public static final String DELTA_REVOCATION_LIST_AT_OID = "2.5.4.53";

    // DmdName
    public static final String DMD_NAME_AT = "dmdName";
    public static final String DMD_NAME_AT_OID = "2.5.4.54";

    //-------------------------------------------------------------------------
    // cosine AttributeTypes
    //-------------------------------------------------------------------------
    // TextEncodedORAddress AT
    public static final String TEXT_ENCODED_OR_ADDRESS_AT = "textEncodedORAddress";
    public static final String TEXT_ENCODED_OR_ADDRESS_AT_OID = "0.9.2342.19200300.100.1.2";

    // Info AT
    public static final String INFO_AT = "info";
    public static final String INFO_AT_OID = "0.9.2342.19200300.100.1.4";

    // Drink AT
    public static final String DRINK_AT = "drink";
    public static final String FAVOURITE_DRINK_AT = "favouriteDrink";
    public static final String DRINK_AT_OID = "0.9.2342.19200300.100.1.5";

    // RoomNumber AT
    public static final String ROOM_NUMBER_AT = "roomNumber";
    public static final String ROOM_NUMBER_AT_OID = "0.9.2342.19200300.100.1.6";

    // Photo AT
    public static final String PHOTO_AT = "photo";
    public static final String PHOTO_AT_OID = "0.9.2342.19200300.100.1.7";

    // UserClass AT
    public static final String USER_CLASS_AT = "userClass";
    public static final String USER_CLASS_AT_OID = "0.9.2342.19200300.100.1.8";

    // Host AT
    public static final String HOST_AT = "host";
    public static final String HOST_AT_OID = "0.9.2342.19200300.100.1.9";

    // Manager AT
    public static final String MANAGER_AT = "manager";
    public static final String MANAGER_AT_OID = "0.9.2342.19200300.100.1.10";

    // DocumentIdentifier AT
    public static final String DOCUMENT_IDENTIFIER_AT = "documentIdentifier";
    public static final String DOCUMENT_IDENTIFIER_AT_OID = "0.9.2342.19200300.100.1.11";

    // DocumentTitle AT
    public static final String DOCUMENT_TITLE_AT = "documentTitle";
    public static final String DOCUMENT_TITLE_AT_OID = "0.9.2342.19200300.100.1.12";

    // DocumentVersion AT
    public static final String DOCUMENT_VERSION_AT = "documentVersion";
    public static final String DOCUMENT_VERSION_AT_OID = "0.9.2342.19200300.100.1.13";

    // DocumentAuthor AT
    public static final String DOCUMENT_AUTHOR_AT = "documentAuthor";
    public static final String DOCUMENT_AUTHOR_AT_OID = "0.9.2342.19200300.100.1.14";

    // DocumentLocation AT
    public static final String DOCUMENT_LOCATION_AT = "documentLocation";
    public static final String DOCUMENT_LOCATION_AT_OID = "0.9.2342.19200300.100.1.15";

    // HomePhone AT
    public static final String HOME_PHONE_AT = "homePhone";
    public static final String HOME_TELEPHONE_NUMBER_AT = "homeTelephoneNumber";
    public static final String HOME_PHONE_AT_OID = "0.9.2342.19200300.100.1.20";

    // Secretary AT
    public static final String SECRETARY_AT = "secretary";
    public static final String SECRETARY_AT_OID = "0.9.2342.19200300.100.1.21";

    // OtherMailbox AT
    public static final String OTHER_MAILBOX_AT = "otherMailbox";
    public static final String OTHER_MAILBOX_AT_OID = "0.9.2342.19200300.100.1.22";

    // ARecord AT
    public static final String A_RECORD_AT = "aRecord";
    public static final String A_RECORD_AT_OID = "0.9.2342.19200300.100.1.26";

    // MDRecord AT
    public static final String MD_RECORD_AT = "mDRecord";
    public static final String MD_RECORD_AT_OID = "0.9.2342.19200300.100.1.27";

    // MXRecord AT
    public static final String MX_RECORD_AT = "mXRecord";
    public static final String MX_RECORD_AT_OID = "0.9.2342.19200300.100.1.28";

    // NSRecord AT
    public static final String NS_RECORD_AT = "nSRecord";
    public static final String NS_RECORD_AT_OID = "0.9.2342.19200300.100.1.29";

    // SOARecord AT
    public static final String SOA_RECORD_AT = "sOARecord";
    public static final String SOA_RECORD_AT_OID = "0.9.2342.19200300.100.1.30";

    // CNAMERecord AT
    public static final String CNAME_RECORD_AT = "cNAMERecord";
    public static final String CNAME_RECORD_AT_OID = "0.9.2342.19200300.100.1.31";

    // AssociatedName AT
    public static final String ASSOCIATED_NAME_AT = "associatedName";
    public static final String ASSOCIATED_NAME_AT_OID = "0.9.2342.19200300.100.1.38";

    // HomePostalAddress AT
    public static final String HOME_POSTAL_ADDRESS_AT = "homePostalAddress";
    public static final String HOME_POSTAL_ADDRESS_AT_OID = "0.9.2342.19200300.100.1.39";

    // PersonalTitle AT
    public static final String PERSONAL_TITLE_AT = "personalTitle";
    public static final String PERSONAL_TITLE_AT_OID = "0.9.2342.19200300.100.1.40";

    // Mobile AT
    public static final String MOBILE_AT = "mobile";
    public static final String MOBILE_TELEPHONE_NUMBER_AT = "mobileTelephoneNumber";
    public static final String MOBILE_AT_OID = "0.9.2342.19200300.100.1.41";

    // Pager AT
    public static final String PAGER_AT = "pager";
    public static final String PAGER_TELEPHONE_NUMBER_AT = "pagerTelephoneNumber";
    public static final String PAGER_AT_OID = "0.9.2342.19200300.100.1.42";

    // Co AT
    public static final String CO_AT = "co";
    public static final String FRIENDLY_COUNTRY_NAME_CO_AT = "friendlyCountryName";
    public static final String CO_AT_OID = "0.9.2342.19200300.100.1.43";

    // UniqueIdentifier AT
    public static final String UNIQUE_IDENTIFIER_AT = "uniqueIdentifier";
    public static final String UNIQUE_IDENTIFIER_AT_OID = "0.9.2342.19200300.100.1.44";

    // OrganizationalStatus AT
    public static final String ORGANIZATIONAL_STATUS_AT = "organizationalStatus";
    public static final String ORGANIZATIONAL_STATUS_AT_OID = "0.9.2342.19200300.100.1.45";

    // JanetMailbox AT
    public static final String JANET_MAILBOX_AT = "janetMailbox";
    public static final String JANET_MAILBOX_AT_OID = "0.9.2342.19200300.100.1.46";

    // MailPreferenceOption AT
    public static final String MAIL_PREFERENCE_OPTION_AT = "mailPreferenceOption";
    public static final String MAIL_PREFERENCE_OPTION_AT_OID = "0.9.2342.19200300.100.1.47";

    // BuildingName AT
    public static final String BUILDING_NAME_AT = "buildingName";
    public static final String BUILDING_NAME_AT_OID = "0.9.2342.19200300.100.1.48";

    // DSAQuality AT
    public static final String DSA_QUALITY_AT = "dSAQuality";
    public static final String DSA_QUALITY_AT_OID = "0.9.2342.19200300.100.1.49";

    // SingleLevelQuality AT
    public static final String SINGLE_LEVEL_QUALITY_AT = "singleLevelQuality";
    public static final String SINGLE_LEVEL_QUALITY_AT_OID = "0.9.2342.19200300.100.1.50";

    // SubtreeMinimumQuality AT
    public static final String SUBTREE_MINIMUM_QUALITY_AT = "subtreeMinimumQuality";
    public static final String SUBTREE_MINIMUM_QUALITY_AT_OID = "0.9.2342.19200300.100.1.51";

    // SubtreeMaximumQuality AT
    public static final String SUBTREE_MAXIMUM_QUALITY_AT = "subtreeMaximumQuality";
    public static final String SUBTREE_MAXIMUM_QUALITY_AT_OID = "0.9.2342.19200300.100.1.52";

    // PersonalSignature AT
    public static final String PERSONAL_SIGNATURE_AT = "personalSignature";
    public static final String PERSONAL_SIGNATURE_AT_OID = "0.9.2342.19200300.100.1.53";

    // DITRedirect AT
    public static final String DIT_REDIRECT_AT = "dITRedirect";
    public static final String DIT_REDIRECT_AT_OID = "0.9.2342.19200300.100.1.54";

    // Audio AT
    public static final String AUDIO_AT = "audio";
    public static final String AUDIO_AT_OID = "0.9.2342.19200300.100.1.55";

    // DocumentPublisher AT
    public static final String DOCUMENT_PUBLISHER_AT = "documentPublisher";
    public static final String DOCUMENT_PUBLISHER_AT_OID = "0.9.2342.19200300.100.1.56";

    //-------------------------------------------------------------------------
    // inetorgperson AttributeTypes
    //-------------------------------------------------------------------------
    // JpegPhoto
    public static final String JPEG_PHOTO_AT = "jpegPhoto";
    public static final String JPEG_PHOTO_AT_OID = "0.9.2342.19200300.100.1.60";

    // CarLicense
    public static final String CAR_LICENSE_AT = "carLicense";
    public static final String CAR_LICENSE_AT_OID = "2.16.840.1.113730.3.1.1";

    // DepartmentNumber
    public static final String DEPARTMENT_NUMBER_AT = "departmentNumber";
    public static final String DEPARTMENT_NUMBER_AT_OID = "2.16.840.1.113730.3.1.2";

    // EmployeeNumber
    public static final String EMPLOYEE_NUMBER_AT = "employeeNumber";
    public static final String EMPLOYEE_NUMBER_AT_OID = "2.16.840.1.113730.3.1.3";

    // EmployeeType
    public static final String EMPLOYEE_TYPE_AT = "employeeType";
    public static final String EMPLOYEE_TYPE_AT_OID = "2.16.840.1.113730.3.1.4";

    // PreferredLanguage
    public static final String PREFERRED_LANGUAGE_AT = "preferredLanguage";
    public static final String PREFERRED_LANGUAGE_AT_OID = "2.16.840.1.113730.3.1.39";

    // UserSMIMECertificate
    public static final String USER_SMIME_CERTIFICATE_AT = "userSMIMECertificate";
    public static final String USER_SMIME_CERTIFICATE_AT_OID = "2.16.840.1.113730.3.1.40";

    // UserPKCS12
    public static final String USER_PKCS12_AT = "userPKCS12";
    public static final String USER_PKCS12_AT_OID = "2.16.840.1.113730.3.1.216";

    // DisplayName
    public static final String DISPLAY_NAME_AT = "displayName";
    public static final String DISPLAY_NAME_AT_OID = "2.16.840.1.113730.3.1.241";

    //-------------------------------------------------------------------------
    // nis AttributeTypes
    //-------------------------------------------------------------------------
    // UidNumber AT
    public static final String UID_NUMBER_AT = "uidNumber";
    public static final String UID_NUMBER_AT_OID = "1.3.6.1.1.1.1.0";

    // GidNumber AT
    public static final String GID_NUMBER_AT = "gidNumber";
    public static final String GID_NUMBER_AT_OID = "1.3.6.1.1.1.1.1";

    // Gecos AT
    public static final String GECOS_AT = "gecos";
    public static final String GECOS_AT_OID = "1.3.6.1.1.1.1.2";

    // HomeDirectory AT
    public static final String HOME_DIRECTORY_AT = "homeDirectory";
    public static final String HOME_DIRECTORY_AT_OID = "1.3.6.1.1.1.1.3";

    // LoginShell AT
    public static final String LOGIN_SHELL_AT = "loginShell";
    public static final String LOGIN_SHELL_AT_OID = "1.3.6.1.1.1.1.4";

    // ShadowLastChange AT
    public static final String SHADOW_LAST_CHANGE_AT = "shadowLastChange";
    public static final String SHADOW_LAST_CHANGE_AT_OID = "1.3.6.1.1.1.1.5";

    // ShadowMin AT
    public static final String SHADOW_MIN_AT = "shadowMin";
    public static final String SHADOW_MIN_AT_OID = "1.3.6.1.1.1.1.6";

    // ShadowMax AT
    public static final String SHADOW_MAX_AT = "shadowMax";
    public static final String SHADOW_MAX_AT_OID = "1.3.6.1.1.1.1.7";

    // ShadowWarning AT
    public static final String SHADOW_WARNING_AT = "shadowWarning";
    public static final String SHADOW_WARNING_AT_OID = "1.3.6.1.1.1.1.8";

    // ShadowInactive AT
    public static final String SHADOW_INACTIVE_AT = "shadowInactive";
    public static final String SHADOW_INACTIVE_AT_OID = "1.3.6.1.1.1.1.9";

    // ShadowExpire AT
    public static final String SHADOW_EXPIRE_AT = "shadowExpire";
    public static final String SHADOW_EXPIRE_AT_OID = "1.3.6.1.1.1.1.10";

    // ShadowFlag AT
    public static final String SHADOW_FLAG_AT = "shadowFlag";
    public static final String SHADOW_FLAG_AT_OID = "1.3.6.1.1.1.1.11";

    // MemberUid AT
    public static final String MEMBER_UID_AT = "memberUid";
    public static final String MEMBER_UID_AT_OID = "1.3.6.1.1.1.1.12";

    // MemberNisNetgroup AT
    public static final String MEMBER_NIS_NETGROUP_AT = "memberNisNetgroup";
    public static final String MEMBER_NIS_NETGROUP_AT_OID = "1.3.6.1.1.1.1.13";

    // NisNetgroupTriple AT
    public static final String NIS_NETGROUP_TRIPLE_AT = "nisNetgroupTriple";
    public static final String NIS_NETGROUP_TRIPLE_AT_OID = "1.3.6.1.1.1.1.14";

    // IpServicePort AT
    public static final String IP_SERVICE_PORT_AT = "ipServicePort";
    public static final String IP_SERVICE_PORT_AT_OID = "1.3.6.1.1.1.1.15";

    // IpServiceProtocol AT
    public static final String IP_SERVICE_PROTOCOL_AT = "ipServiceProtocol";
    public static final String IP_SERVICE_PROTOCOL_AT_OID = "1.3.6.1.1.1.1.16";

    // IpProtocolNumber AT
    public static final String IP_PROTOCOL_NUMBER_AT = "ipProtocolNumber";
    public static final String IP_PROTOCOL_NUMBER_AT_OID = "1.3.6.1.1.1.1.17";

    // OncRpcNumber AT
    public static final String ONC_RPC_NUMBER_AT = "oncRpcNumber";
    public static final String ONC_RPC_NUMBER_AT_OID = "1.3.6.1.1.1.1.18";

    // IpHostNumber AT
    public static final String IP_HOST_NUMBER_AT = "ipHostNumber";
    public static final String IP_HOST_NUMBER_AT_OID = "1.3.6.1.1.1.1.19";

    // IpNetworkNumber AT
    public static final String IP_NETWORK_NUMBER_AT = "ipNetworkNumber";
    public static final String IP_NETWORK_NUMBER_AT_OID = "1.3.6.1.1.1.1.20";

    // IpNetmaskNumber AT
    public static final String IP_NETMASK_NUMBER_AT = "ipNetmaskNumber";
    public static final String IP_NETMASK_NUMBER_AT_OID = "1.3.6.1.1.1.1.21";

    // MacAddress AT
    public static final String MAC_ADDRESS_AT = "macAddress";
    public static final String MAC_ADDRESS_AT_OID = "1.3.6.1.1.1.1.22";

    // BootParameter AT
    public static final String BOOT_PARAMETER_AT = "bootParameter";
    public static final String BOOT_PARAMETER_AT_OID = "1.3.6.1.1.1.1.23";

    // BootFile AT
    public static final String BOOT_FILE_AT = "bootFile";
    public static final String BOOT_FILE_AT_OID = "1.3.6.1.1.1.1.24";

    // NisMapName AT
    public static final String NIS_MAP_NAME_AT = "nisMapName";
    public static final String NIS_MAP_NAME_AT_OID = "1.3.6.1.1.1.1.26";

    // NisMapEntry AT
    public static final String NIS_MAP_ENTRY_AT = "nisMapEntry";
    public static final String NIS_MAP_ENTRY_AT_OID = "1.3.6.1.1.1.1.27";

    //-------------------------------------------------------------------------
    // pwdpolicy AttributeTypes
    //-------------------------------------------------------------------------
    // PwdAttribute AT
    public static final String PWD_ATTRIBUTE_AT = "pwdAttribute";
    public static final String PWD_ATTRIBUTE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.1";

    // PwdMinAge AT
    public static final String PWD_MIN_AGE_AT = "pwdMinAge";
    public static final String PWD_MIN_AGE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.2";

    // PwdMaxAge AT
    public static final String PWD_MAX_AGE_AT = "pwdMaxAge";
    public static final String PWD_MAX_AGE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.3";

    // PwdInHistory AT
    public static final String PWD_IN_HISTORY_AT = "pwdInHistory";
    public static final String PWD_IN_HISTORY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.4";

    // PwdCheckQuality AT
    public static final String PWD_CHECK_QUALITY_AT = "pwdCheckQuality";
    public static final String PWD_CHECK_QUALITY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.5";

    // PwdMinLength AT
    public static final String PWD_MIN_LENGTH_AT = "pwdMinLength";
    public static final String PWD_MIN_LENGTH_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.6";

    // PwdExpireWarning AT
    public static final String PWD_EXPIRE_WARNING_AT = "pwdExpireWarning";
    public static final String PWD_EXPIRE_WARNING_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.7";

    // PwdGraceAuthNLimit AT
    public static final String PWD_GRACE_AUTH_N_LIMIT_AT = "pwdGraceAuthNLimit";
    public static final String PWD_GRACE_AUTH_N_LIMIT_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.8";

    // PwdLockout AT
    public static final String PWD_LOCKOUT_AT = "pwdLockout";
    public static final String PWD_LOCKOUT_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.9";

    // PwdLockoutDuration AT
    public static final String PWD_LOCKOUT_DURATION_AT = "pwdLockoutDuration";
    public static final String PWD_LOCKOUT_DURATION_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.10";

    // PwdMaxFailure AT
    public static final String PWD_MAX_FAILURE_AT = "pwdMaxFailure";
    public static final String PWD_MAX_FAILURE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.11";

    // PwdFailureCountInterval AT
    public static final String PWD_FAILURE_COUNT_INTERVAL_AT = "pwdFailureCountInterval";
    public static final String PWD_FAILURE_COUNT_INTERVAL_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.12";

    // PwdMustChange AT
    public static final String PWD_MUST_CHANGE_AT = "pwdMustChange";
    public static final String PWD_MUST_CHANGE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.13";

    // PwdAllowUserChange AT
    public static final String PWD_ALLOW_USER_CHANGE_AT = "pwdAllowUserChange";
    public static final String PWD_ALLOW_USER_CHANGE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.14";

    // PwdSafeModify AT
    public static final String PWD_SAFE_MODIFY_AT = "pwdSafeModify";
    public static final String PWD_SAFE_MODIFY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.15";

    // PwdChangedTime AT
    public static final String PWD_CHANGED_TIME_AT = "pwdChangedTime";
    public static final String PWD_CHANGED_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.16";

    // PwdAccountLockedTime AT
    public static final String PWD_ACCOUNT_LOCKED_TIME_AT = "pwdAccountLockedTime";
    public static final String PWD_ACCOUNT_LOCKED_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.17";

    // PwdFailureTime AT
    public static final String PWD_FAILURE_TIME_AT = "pwdFailureTime";
    public static final String PWD_FAILURE_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.19";

    // PwdHistory AT
    public static final String PWD_HISTORY_AT = "pwdHistory";
    public static final String PWD_HISTORY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.20";

    // PwdGraceUseTime AT
    public static final String PWD_GRACE_USE_TIME_AT = "pwdGraceUseTime";
    public static final String PWD_GRACE_USE_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.21";

    // PwdReset AT
    public static final String PWD_RESET_AT = "pwdReset";
    public static final String PWD_RESET_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.22";

    // PwdPolicySubentry AT
    public static final String PWD_POLICY_SUBENTRY_AT = "pwdPolicySubentry";
    public static final String PWD_POLICY_SUBENTRY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.23";

    // PwdMinDelay AT
    public static final String PWD_MIN_DELAY_AT = "pwdMinDelay";
    public static final String PWD_MIN_DELAY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.24";

    // PwdMaxDelay AT
    public static final String PWD_MAX_DELAY_AT = "pwdMaxDelay";
    public static final String PWD_MAX_DELAY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.25";

    // PwdMaxIdle AT
    public static final String PWD_MAX_IDLE_AT = "pwdMaxIdle";
    public static final String PWD_MAX_IDLE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.26";

    // PwdStartTime AT
    public static final String PWD_START_TIME_AT = "pwdStartTime";
    public static final String PWD_START_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.27";

    // PwdEndTime AT
    public static final String PWD_END_TIME_AT = "pwdEndTime";
    public static final String PWD_END_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.28";

    // PwdLastSuccess AT
    public static final String PWD_LAST_SUCCESS_AT = "pwdLastSuccess";
    public static final String PWD_LAST_SUCCESS_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.29";

    // PwdGraceExpire AT
    public static final String PWD_GRACE_EXPIRE_AT = "pwdGraceExpire";
    public static final String PWD_GRACE_EXPIRE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.30";

    // PwdMaxLength AT
    public static final String PWD_MAX_LENGTH_AT = "pwdMaxLength";
    public static final String PWD_MAX_LENGTH_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.31";

    //-------------------------------------------------------------------------
    // system AttributeTypes
    //-------------------------------------------------------------------------
    // VendorName
    public static final String VENDOR_NAME_AT = "vendorName";
    public static final String VENDOR_NAME_AT_OID = "1.3.6.1.1.4";

    // VendorVersion
    public static final String VENDOR_VERSION_AT = "vendorVersion";
    public static final String VENDOR_VERSION_AT_OID = "1.3.6.1.1.5";

    // LabeledURI
    public static final String LABELED_URI_AT = "labeledURI";
    public static final String LABELED_URI_AT_OID = "1.3.6.1.4.1.250.1.57";

    // EntryTtl
    public static final String ENTRY_TTL_AT = "entryTtl";
    public static final String ENTRY_TTL_AT_OID = "1.3.6.1.4.1.1466.101.119.3";

    // DynamicSubtrees
    public static final String DYNAMIC_SUBTREES_AT = "dynamicSubtrees";
    public static final String DYNAMIC_SUBTREES_AT_OID = "1.3.6.1.4.1.1466.101.119.4";

    // NamingContexts
    public static final String NAMING_CONTEXTS_AT = "namingContexts";
    public static final String NAMING_CONTEXTS_AT_OID = "1.3.6.1.4.1.1466.101.120.5";

    // AltServer
    public static final String ALT_SERVER_AT = "altServer";
    public static final String ALT_SERVER_AT_OID = "1.3.6.1.4.1.1466.101.120.6";

    // SupportedExtension
    public static final String SUPPORTED_EXTENSION_AT = "supportedExtension";
    public static final String SUPPORTED_EXTENSION_AT_OID = "1.3.6.1.4.1.1466.101.120.7";

    // SupportedControl
    public static final String SUPPORTED_CONTROL_AT = "supportedControl";
    public static final String SUPPORTED_CONTROL_AT_OID = "1.3.6.1.4.1.1466.101.120.13";

    // SupportedSASLMechanisms
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

    // ObjectClass
    public static final String OBJECT_CLASS_AT = "objectClass";
    public static final String OBJECT_CLASS_AT_OID = "2.5.4.0";

    // AliasedObjectName
    public static final String ALIASED_OBJECT_NAME_AT = "aliasedObjectName";
    public static final String ALIASED_ENTRY_NAME_AT = "aliasedEntryName";
    public static final String ALIASED_OBJECT_NAME_AT_OID = "2.5.4.1";

    // Cn
    public static final String CN_AT = "cn";
    public static final String COMMON_NAME_AT = "commonName";
    public static final String CN_AT_OID = "2.5.4.3";

    // UserPassword
    public static final String USER_PASSWORD_AT = "userPassword";
    public static final String USER_PASSWORD_AT_OID = "2.5.4.35";

    // Name
    public static final String NAME_AT = "name";
    public static final String NAME_AT_OID = "2.5.4.41";

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

    // Ref
    public static final String REF_AT = "ref";
    public static final String REF_AT_OID = "2.16.840.1.113730.3.1.34";

    //-------------------------------------------------------------------------
    // Various other AttributeTypes
    //-------------------------------------------------------------------------
    // apache AttributeTypes
    //-------------------------------------------------------------------------
    // EntryUUID
    public static final String ENTRY_UUID_AT = "entryUUID";
    public static final String ENTRY_UUID_AT_OID = "1.3.6.1.1.16.4";

    // EntryDN
    public static final String ENTRY_DN_AT = "entryDN";
    public static final String ENTRY_DN_AT_OID = "1.3.6.1.1.20";

    // entryCSN
    public static final String ENTRY_CSN_AT = "entryCSN";
    public static final String ENTRY_CSN_AT_OID = "1.3.6.1.4.1.4203.666.1.7";

    // contextCSN
    public static final String CONTEXT_CSN_AT = "contextCSN";
    public static final String CONTEXT_CSN_AT_OID = "1.3.6.1.4.1.4203.666.1.25";

    // PrescriptiveACI
    public static final String PRESCRIPTIVE_ACI_AT = "prescriptiveACI";
    public static final String PRESCRIPTIVE_ACI_AT_OID = "2.5.24.4";

    // EntryACI
    public static final String ENTRY_ACI_AT = "entryACI";
    public static final String ENTRY_ACI_AT_OID = "2.5.24.5";

    // SubentryACI
    public static final String SUBENTRY_ACI_AT = "subentryACI";
    public static final String SUBENTRY_ACI_AT_OID = "2.5.24.6";

    // PrescriptiveTriggerSpecification
    public static final String PRESCRIPTIVE_TRIGGER_SPECIFICATION_AT = "prescriptiveTriggerSpecification";
    public static final String PRESCRIPTIVE_TRIGGER_SPECIFICATION_AT_OID = "1.3.6.1.4.1.18060.0.4.1.2.25";
    
    // EntryTriggerSpecification
    public static final String ENTRY_TRIGGER_SPECIFICATION_AT = "entryTriggerSpecification";
    public static final String ENTRY_TRIGGER_SPECIFICATION_AT_OID = "1.3.6.1.4.1.18060.0.4.1.2.26";
    
    // Comparators
    public static final String COMPARATORS_AT = "comparators";
    public static final String COMPARATORS_AT_OID = "1.3.6.1.4.1.18060.0.4.1.2.32";

    // Normalizers
    public static final String NORMALIZERS_AT = "normalizers";
    public static final String NORMALIZERS_AT_OID = "1.3.6.1.4.1.18060.0.4.1.2.33";

    // SyntaxCheckers
    public static final String SYNTAX_CHECKERS_AT = "syntaxCheckers";
    public static final String SYNTAX_CHECKERS_AT_OID = "1.3.6.1.4.1.18060.0.4.1.2.34";

    //-------------------------------------------------------------------------
    // Unkown schema AttributeTypes
    //-------------------------------------------------------------------------
    // ExcludeAllCollectiveAttributes
    public static final String EXCLUDE_ALL_COLLECTIVE_ATTRIBUTES_AT = "excludeAllCollectiveAttributes";
    public static final String EXCLUDE_ALL_COLLECTIVE_ATTRIBUTES_AT_OID = "2.5.18.0";

    // governingStructureRule
    public static final String GOVERNING_STRUCTURE_RULE_AT = "governingStructureRule";
    public static final String GOVERNING_STRUCTURE_RULE_AT_OID = "2.5.21.10";

    // AccessControlScheme
    public static final String ACCESS_CONTROL_SCHEME_AT = "accessControlScheme";
    public static final String ACCESS_CONTROL_SCHEME_OID = "2.5.24.1";

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
