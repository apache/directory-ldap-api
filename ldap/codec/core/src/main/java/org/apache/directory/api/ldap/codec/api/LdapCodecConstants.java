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
package org.apache.directory.api.ldap.codec.api;


/**
 * This class contains a list of constants used in the LDAP coder/decoder.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class LdapCodecConstants
{
    /** The Base Object scope constants */
    public static final int SCOPE_BASE_OBJECT = 0;

    /** The Single Level scope constants */
    public static final int SCOPE_SINGLE_LEVEL = 1;

    /** The Whole Subtree scope constants */
    public static final int SCOPE_WHOLE_SUBTREE = 2;

    /** The DerefAlias constants */
    public static final int NEVER_DEREF_ALIASES = 0;

    /** The Deref In Searching constants */
    public static final int DEREF_IN_SEARCHING = 1;

    /** The Deref Finding Base constants */
    public static final int DEREF_FINDING_BASE_OBJ = 2;

    /** The Deref Always constants */
    public static final int DEREF_ALWAYS = 3;

    /** The Add operation */
    public static final int OPERATION_ADD = 0;

    /** The Delete operation */
    public static final int OPERATION_DELETE = 1;

    /** The Replace operation */
    public static final int OPERATION_REPLACE = 2;

    /** The Increment operation */
    public static final int OPERATION_INCREMENT = 3;

    /** The Equality Match filter */
    public static final int EQUALITY_MATCH_FILTER = 0;

    /** The Greater or Equal filter */
    public static final int GREATER_OR_EQUAL_FILTER = 1;

    /** The Less or Equal filter */
    public static final int LESS_OR_EQUAL_FILTER = 2;

    /** The Approx Match filter */
    public static final int APPROX_MATCH_FILTER = 3;

    /** LDAP contextual tags */
    /** Unbind Request tag */
    public static final byte UNBIND_REQUEST_TAG = 0x42;

    /** UnbDelind Request tag */
    public static final byte DEL_REQUEST_TAG = 0x4A;

    /** Abandon Request tag */
    public static final byte ABANDON_REQUEST_TAG = 0x50;

    /** Bind Request tag */
    public static final byte BIND_REQUEST_TAG = 0x60;

    /** Bind Response tag */
    public static final byte BIND_RESPONSE_TAG = 0x61;

    /** Unbind Request tag */
    public static final byte SEARCH_REQUEST_TAG = 0x63;

    /** Search Result Entry Response tag */
    public static final byte SEARCH_RESULT_ENTRY_TAG = 0x64;

    /** Search Result Done Response tag */
    public static final byte SEARCH_RESULT_DONE_TAG = 0x65;

    /** Modify Request tag */
    public static final byte MODIFY_REQUEST_TAG = 0x66;

    /** Modify Response tag */
    public static final byte MODIFY_RESPONSE_TAG = 0x67;

    /** Add Request tag */
    public static final byte ADD_REQUEST_TAG = 0x68;

    /** Add Response tag */
    public static final byte ADD_RESPONSE_TAG = 0x69;

    /** Del Response tag */
    public static final byte DEL_RESPONSE_TAG = 0x6B;

    /** ModifyDN Request tag */
    public static final byte MODIFY_DN_REQUEST_TAG = 0x6C;

    /** ModifyDN Response tag */
    public static final byte MODIFY_DN_RESPONSE_TAG = 0x6D;

    /** Compare Request tag */
    public static final byte COMPARE_REQUEST_TAG = 0x6E;

    /** Compare Response tag */
    public static final byte COMPARE_RESPONSE_TAG = 0x6F;

    /** Search Result Reference Response tag */
    public static final byte SEARCH_RESULT_REFERENCE_TAG = 0x73;

    /** Extended Request tag */
    public static final byte EXTENDED_REQUEST_TAG = 0x77;

    /** Extended Response tag */
    public static final byte EXTENDED_RESPONSE_TAG = 0x78;

    /** Intermediate Response tag */
    public static final byte INTERMEDIATE_RESPONSE_TAG = 0x79;

    // The following tags are ints, because bytes above 127 are negative
    // numbers, and we can't use them as array indexes.
    /** Bind Request Simple tag */
    public static final int BIND_REQUEST_SIMPLE_TAG = 0x80;

    /** Extended Request Name tag */
    public static final int EXTENDED_REQUEST_NAME_TAG = 0x80;

    /** ModifyDN Request New Superior tag */
    public static final int MODIFY_DN_REQUEST_NEW_SUPERIOR_TAG = 0x80;

    /** Substrings Filter Initial tag */
    public static final int SUBSTRINGS_FILTER_INITIAL_TAG = 0x80;

    /** Extended Request Value tag */
    public static final int EXTENDED_REQUEST_VALUE_TAG = 0x81;

    /** Matching Rule ID tag */
    public static final int MATCHING_RULE_ID_TAG = 0x81;

    /** Substrings Filter Any tag */
    public static final int SUBSTRINGS_FILTER_ANY_TAG = 0x81;

    /** Matching Rule Type tag */
    public static final int MATCHING_RULE_TYPE_TAG = 0x82;

    /** Substrinngs Filter Final tag */
    public static final int SUBSTRINGS_FILTER_FINAL_TAG = 0x82;

    /** Match Value tag */
    public static final int MATCH_VALUE_TAG = 0x83;

    /** DN Attributes Filter tag */
    public static final int DN_ATTRIBUTES_FILTER_TAG = 0x84;

    /** Server SASL Credentials tag */
    public static final int SERVER_SASL_CREDENTIAL_TAG = 0x87;

    /** Present Filter tag */
    public static final int PRESENT_FILTER_TAG = 0x87;

    /** Extended Response Name tag */
    public static final int EXTENDED_RESPONSE_NAME_TAG = 0x8A;

    /** Extended Response Value tag */
    public static final int EXTENDED_RESPONSE_VALUE_TAG = 0x8B;

    /** Controls tag */
    public static final int CONTROLS_TAG = 0xA0;

    /** And Filter tag */
    public static final int AND_FILTER_TAG = 0xA0;

    /** Intermediate Response Name tag */
    public static final int INTERMEDIATE_RESPONSE_NAME_TAG = 0x80;

    /** Intermediate Response Value tag */
    public static final int INTERMEDIATE_RESPONSE_VALUE_TAG = 0x81;

    /** Or Filter tag */
    public static final int OR_FILTER_TAG = 0xA1;

    /** Not Filter tag */
    public static final int NOT_FILTER_TAG = 0xA2;

    /** Bind Request SASL tag */
    public static final int BIND_REQUEST_SASL_TAG = 0xA3;

    /** LDAP Result Refrral Sequence Tag */
    public static final int LDAP_RESULT_REFERRAL_SEQUENCE_TAG = 0xA3;

    /** Equality Match Filter tag */
    public static final int EQUALITY_MATCH_FILTER_TAG = 0xA3;

    /** Substrings Filter tag */
    public static final int SUBSTRINGS_FILTER_TAG = 0xA4;

    /** Greater Or Equal Filter tag */
    public static final int GREATER_OR_EQUAL_FILTER_TAG = 0xA5;

    /** Ledss or Equal Filter tag */
    public static final int LESS_OR_EQUAL_FILTER_TAG = 0xA6;

    /** Approox Match Filter tag */
    public static final int APPROX_MATCH_FILTER_TAG = 0xA8;

    /** Extensible Match Filter tag */
    public static final int EXTENSIBLE_MATCH_FILTER_TAG = 0xA9;

    /**
     * Private constructor.
     */
    private LdapCodecConstants()
    {
    }
}
