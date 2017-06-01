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

package org.apache.directory.api.ldap.model.schema;


import java.io.IOException;

import org.apache.directory.api.util.Strings;
import org.apache.directory.api.util.exception.InvalidCharacterException;


/**
 * 
 * This class implements the 6 steps described in RFC 4518
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class PrepareString
{
    /** A flag used to lowercase chars during the map process */
    private static final boolean CASE_SENSITIVE = true;

    /** A flag used to keep casing during the map process */
    private static final boolean IGNORE_CASE = false;

    /** All the possible combining marks */
    private static final char[][] COMBINING_MARKS = new char[][]
        {
            { 0x0300, 0x034F },
            { 0x0360, 0x036F },
            { 0x0483, 0x0486 },
            { 0x0488, 0x0489 },
            { 0x0591, 0x05A1 },
            { 0x05A3, 0x05B9 },
            { 0x05BB, 0x05BC },
            { 0x05BF, 0x05BF },
            { 0x05C1, 0x05C2 },
            { 0x05C4, 0x05C4 },
            { 0x064B, 0x0655 },
            { 0x0670, 0x0670 },
            { 0x06D6, 0x06DC },
            { 0x06DE, 0x06E4 },
            { 0x06E7, 0x06E8 },
            { 0x06EA, 0x06ED },
            { 0x0711, 0x0711 },
            { 0x0730, 0x074A },
            { 0x07A6, 0x07B0 },
            { 0x0901, 0x0903 },
            { 0x093C, 0x093C },
            { 0x093E, 0x094F },
            { 0x0951, 0x0954 },
            { 0x0962, 0x0963 },
            { 0x0981, 0x0983 },
            { 0x09BC, 0x09BC },
            { 0x09BE, 0x09C4 },
            { 0x09C7, 0x09C8 },
            { 0x09CB, 0x09CD },
            { 0x09D7, 0x09D7 },
            { 0x09E2, 0x09E3 },
            { 0x0A02, 0x0A02 },
            { 0x0A3C, 0x0A3C },
            { 0x0A3E, 0x0A42 },
            { 0x0A47, 0x0A48 },
            { 0x0A4B, 0x0A4D },
            { 0x0A70, 0x0A71 },
            { 0x0A81, 0x0A83 },
            { 0x0ABC, 0x0ABC },
            { 0x0ABE, 0x0AC5 },
            { 0x0AC7, 0x0AC9 },
            { 0x0ACB, 0x0ACD },
            { 0x0B01, 0x0B03 },
            { 0x0B3C, 0x0B3C },
            { 0x0B3E, 0x0B43 },
            { 0x0B47, 0x0B48 },
            { 0x0B4B, 0x0B4D },
            { 0x0B56, 0x0B57 },
            { 0x0B82, 0x0B82 },
            { 0x0BBE, 0x0BC2 },
            { 0x0BC6, 0x0BC8 },
            { 0x0BCA, 0x0BCD },
            { 0x0BD7, 0x0BD7 },
            { 0x0C01, 0x0C03 },
            { 0x0C3E, 0x0C44 },
            { 0x0C46, 0x0C48 },
            { 0x0C4A, 0x0C4D },
            { 0x0C55, 0x0C56 },
            { 0x0C82, 0x0C83 },
            { 0x0CBE, 0x0CC4 },
            { 0x0CC6, 0x0CC8 },
            { 0x0CCA, 0x0CCD },
            { 0x0CD5, 0x0CD6 },
            { 0x0D02, 0x0D03 },
            { 0x0D3E, 0x0D43 },
            { 0x0D46, 0x0D48 },
            { 0x0D4A, 0x0D4D },
            { 0x0D57, 0x0D57 },
            { 0x0D82, 0x0D83 },
            { 0x0DCA, 0x0DCA },
            { 0x0DCF, 0x0DD4 },
            { 0x0DD6, 0x0DD6 },
            { 0x0DD8, 0x0DDF },
            { 0x0DF2, 0x0DF3 },
            { 0x0E31, 0x0E31 },
            { 0x0E34, 0x0E3A },
            { 0x0E47, 0x0E4E },
            { 0x0EB1, 0x0EB1 },
            { 0x0EB4, 0x0EB9 },
            { 0x0EBB, 0x0EBC },
            { 0x0EC8, 0x0ECD },
            { 0x0F18, 0x0F19 },
            { 0x0F35, 0x0F35 },
            { 0x0F37, 0x0F37 },
            { 0x0F39, 0x0F39 },
            { 0x0F3E, 0x0F3F },
            { 0x0F71, 0x0F84 },
            { 0x0F86, 0x0F87 },
            { 0x0F90, 0x0F97 },
            { 0x0F99, 0x0FBC },
            { 0x0FC6, 0x0FC6 },
            { 0x102C, 0x1032 },
            { 0x1036, 0x1039 },
            { 0x1056, 0x1059 },
            { 0x1712, 0x1714 },
            { 0x1732, 0x1734 },
            { 0x1752, 0x1753 },
            { 0x1772, 0x1773 },
            { 0x17B4, 0x17D3 },
            { 0x180B, 0x180D },
            { 0x18A9, 0x18A9 },
            { 0x20D0, 0x20EA },
            { 0x302A, 0x302F },
            { 0x3099, 0x309A },
            { 0xFB1E, 0xFB1E },
            { 0xFE00, 0xFE0F },
            { 0xFE20, 0xFE23 }
    };

    /**
     * The type of String we have to normalize
     */
    public enum StringType
    {
        /** Not a String */
        NOT_STRING,
        
        /** A numeric String */
        NUMERIC_STRING,
        
        /** Case sensitive String */
        CASE_EXACT,
        
        /** IA5 case sensitive String */
        CASE_EXACT_IA5,
        
        /** IA5 case insensitive String */
        CASE_IGNORE_IA5,
        
        /** Case insensitive String list */
        CASE_IGNORE_LIST,
        
        /** Case insensitive String */
        CASE_IGNORE,
        
        /** Directory String */
        DIRECTORY_STRING,
        
        /** Telephone number String */
        TELEPHONE_NUMBER,
        
        /** A word */
        WORD
    }


    /**
     * A private constructor, to avoid instance creation of this static class.
     */
    private PrepareString()
    {
        // Do nothing
    }


    /**
     * Tells if a char is a combining mark.
     *
     * @param c The char to check
     * @return true if the char is a combining mark, false otherwise
     */
    private static boolean isCombiningMark( char c )
    {
        if ( c < COMBINING_MARKS[0][0] )
        {
            return false;
        }

        for ( char[] interval : COMBINING_MARKS )
        {
            if ( ( c >= interval[0] ) && ( c <= interval[1] ) )
            {
                return true;
            }
        }

        return false;
    }


    /**
    *
    * We have to go through 6 steps :
    *
    * 1) Transcode
    * 2) Map
    * 3) Normalize
    * 4) Prohibit
    * 5) Bidi
    * 6) Insignifiant Character Handling
    *
    * The first step is already done, the step (3) is not done.
    *
    * @param str The String to normalize
    * @param type The string type
    * @return A normalized string.
    * @throws IOException If teh normalization failed
    */
    public static String normalize( String str, StringType type ) throws IOException
    {
        switch ( type )
        {
            case NUMERIC_STRING:
                return insignifiantCharNumericString( str );

            case TELEPHONE_NUMBER:
                return insignifiantCharTelephoneNumber( str );

            case CASE_EXACT:
            case CASE_EXACT_IA5:
            case DIRECTORY_STRING:
                try
                {
                    return insignifiantSpacesStringAscii( str, CASE_SENSITIVE );
                }
                catch ( Exception e )
                {
                    return insignifiantSpacesString( str, CASE_SENSITIVE );
                }

            case CASE_IGNORE_IA5:
            case CASE_IGNORE_LIST:
            case CASE_IGNORE:
                try
                {
                    return insignifiantSpacesStringAscii( str, IGNORE_CASE );
                }
                catch ( Exception e )
                {
                    return insignifiantSpacesString( str, IGNORE_CASE );
                }

            case WORD:
                return str;

            default:
                return str;

        }
    }


    /**
     * Execute the mapping step of the string preparation :
     * - suppress useless chars
     * - transform to spaces
     * - lowercase
     * 
     * @param c The char to map
     * @param array The array which will collect the transformed char
     * @param pos The current position in the target
     * @param lowerCase A mask to lowercase the char, if necessary
     * @return The transformed StringBuilder
     */
    // CHECKSTYLE:OFF
    private static int map( char[] src, char[] target, char lowerCase )
    {
        int limit = 0;

        for ( char c : src )
        {
            switch ( c )
            {
                case 0x0000:
                case 0x0001:
                case 0x0002:
                case 0x0003:
                case 0x0004:
                case 0x0005:
                case 0x0006:
                case 0x0007:
                case 0x0008:
                    break;

                case 0x0009:
                case 0x000A:
                case 0x000B:
                case 0x000C:
                case 0x000D:
                    target[limit++] = ( char ) 0x20;
                    break;

                case 0x000E:
                case 0x000F:
                case 0x0010:
                case 0x0011:
                case 0x0012:
                case 0x0013:
                case 0x0014:
                case 0x0015:
                case 0x0016:
                case 0x0017:
                case 0x0018:
                case 0x0019:
                case 0x001A:
                case 0x001B:
                case 0x001C:
                case 0x001D:
                case 0x001E:
                case 0x001F:
                    break;

                case 0x0041:
                case 0x0042:
                case 0x0043:
                case 0x0044:
                case 0x0045:
                case 0x0046:
                case 0x0047:
                case 0x0048:
                case 0x0049:
                case 0x004A:
                case 0x004B:
                case 0x004C:
                case 0x004D:
                case 0x004E:
                case 0x004F:
                case 0x0050:
                case 0x0051:
                case 0x0052:
                case 0x0053:
                case 0x0054:
                case 0x0055:
                case 0x0056:
                case 0x0057:
                case 0x0058:
                case 0x0059:
                case 0x005A:
                    target[limit++] = ( char ) ( c | lowerCase );
                    break;

                case 0x007F:
                case 0x0080:
                case 0x0081:
                case 0x0082:
                case 0x0083:
                case 0x0084:
                    break;

                case 0x0085:
                    target[limit] = ( char ) 0x20;
                    break;

                case 0x0086:
                case 0x0087:
                case 0x0088:
                case 0x0089:
                case 0x008A:
                case 0x008B:
                case 0x008C:
                case 0x008D:
                case 0x008E:
                case 0x008F:
                case 0x0090:
                case 0x0091:
                case 0x0092:
                case 0x0093:
                case 0x0094:
                case 0x0095:
                case 0x0096:
                case 0x0097:
                case 0x0098:
                case 0x0099:
                case 0x009A:
                case 0x009B:
                case 0x009C:
                case 0x009D:
                case 0x009E:
                case 0x009F:
                    break;

                case 0x00A0:
                    target[limit++] = ( char ) 0x20;
                    break;

                case 0x00AD:
                    break;

                case 0x00B5:
                    target[limit++] = ( char ) 0x03BC;
                    break;

                case 0x00C0:
                case 0x00C1:
                case 0x00C2:
                case 0x00C3:
                case 0x00C4:
                case 0x00C5:
                case 0x00C6:
                case 0x00C7:
                case 0x00C8:
                case 0x00C9:
                case 0x00CA:
                case 0x00CB:
                case 0x00CC:
                case 0x00CD:
                case 0x00CE:
                case 0x00CF:
                case 0x00D0:
                case 0x00D1:
                case 0x00D2:
                case 0x00D3:
                case 0x00D4:
                case 0x00D5:
                case 0x00D6:
                case 0x00D8:
                case 0x00D9:
                case 0x00DA:
                case 0x00DB:
                case 0x00DC:
                case 0x00DD:
                case 0x00DE:
                    target[limit++] = ( char ) ( c | lowerCase );
                    break;

                case 0x00DF:
                    target[limit++] = ( char ) 0x0073;
                    target[limit++] = ( char ) 0x0073;
                    break;

                case 0x0100:
                    target[limit++] = ( char ) 0x0101;
                    break;

                case 0x0102:
                    target[limit++] = ( char ) 0x0103;
                    break;

                case 0x0104:
                    target[limit++] = 0x0105;
                    break;

                case 0x0106:
                    target[limit++] = 0x0107;
                    break;

                case 0x0108:
                    target[limit++] = 0x0109;
                    break;

                case 0x010A:
                    target[limit++] = 0x010B;
                    break;

                case 0x010C:
                    target[limit++] = 0x010D;
                    break;

                case 0x010E:
                    target[limit++] = 0x010F;
                    break;

                case 0x0110:
                    target[limit++] = 0x0111;
                    break;

                case 0x0112:
                    target[limit++] = 0x0113;
                    break;

                case 0x0114:
                    target[limit++] = 0x0115;
                    break;

                case 0x0116:
                    target[limit++] = 0x0117;
                    break;

                case 0x0118:
                    target[limit++] = 0x0119;
                    break;

                case 0x011A:
                    target[limit++] = 0x011B;
                    break;

                case 0x011C:
                    target[limit++] = 0x011D;
                    break;

                case 0x011E:
                    target[limit++] = 0x011F;
                    break;

                case 0x0120:
                    target[limit++] = 0x0121;
                    break;

                case 0x0122:
                    target[limit++] = 0x0123;
                    break;

                case 0x0124:
                    target[limit++] = 0x0125;
                    break;

                case 0x0126:
                    target[limit++] = 0x0127;
                    break;

                case 0x0128:
                    target[limit++] = 0x0129;
                    break;

                case 0x012A:
                    target[limit++] = 0x012B;
                    break;

                case 0x012C:
                    target[limit++] = 0x012D;
                    break;

                case 0x012E:
                    target[limit++] = 0x012F;
                    break;

                case 0x0130:
                    target[limit++] = 0x0069;
                    target[limit++] = 0x0307;
                    break;

                case 0x0132:
                    target[limit++] = 0x0133;
                    break;

                case 0x0134:
                    target[limit++] = 0x0135;
                    break;

                case 0x0136:
                    target[limit++] = 0x0137;
                    break;

                case 0x0139:
                    target[limit++] = 0x013A;
                    break;

                case 0x013B:
                    target[limit++] = 0x013C;
                    break;

                case 0x013D:
                    target[limit++] = 0x013E;
                    break;

                case 0x013F:
                    target[limit++] = 0x0140;
                    break;

                case 0x0141:
                    target[limit++] = 0x0142;
                    break;

                case 0x0143:
                    target[limit++] = 0x0144;
                    break;

                case 0x0145:
                    target[limit++] = 0x0146;
                    break;

                case 0x0147:
                    target[limit++] = 0x0148;
                    break;

                case 0x0149:
                    target[limit++] = 0x02BC;
                    target[limit++] = 0x006E;
                    break;

                case 0x014A:
                    target[limit++] = 0x014B;
                    break;

                case 0x014C:
                    target[limit++] = 0x014D;
                    break;

                case 0x014E:
                    target[limit++] = 0x014F;
                    break;

                case 0x0150:
                    target[limit++] = 0x0151;
                    break;

                case 0x0152:
                    target[limit++] = 0x0153;
                    break;

                case 0x0154:
                    target[limit++] = 0x0155;
                    break;

                case 0x0156:
                    target[limit++] = 0x0157;
                    break;

                case 0x0158:
                    target[limit++] = 0x0159;
                    break;

                case 0x015A:
                    target[limit++] = 0x015B;
                    break;

                case 0x015C:
                    target[limit++] = 0x015D;
                    break;

                case 0x015E:
                    target[limit++] = 0x015F;
                    break;

                case 0x0160:
                    target[limit++] = 0x0161;
                    break;

                case 0x0162:
                    target[limit++] = 0x0163;
                    break;

                case 0x0164:
                    target[limit++] = 0x0165;
                    break;

                case 0x0166:
                    target[limit++] = 0x0167;
                    break;

                case 0x0168:
                    target[limit++] = 0x0169;
                    break;

                case 0x016A:
                    target[limit++] = 0x016B;
                    break;

                case 0x016C:
                    target[limit++] = 0x016D;
                    break;

                case 0x016E:
                    target[limit++] = 0x016F;
                    break;

                case 0x0170:
                    target[limit++] = 0x0171;
                    break;

                case 0x0172:
                    target[limit++] = 0x0173;
                    break;

                case 0x0174:
                    target[limit++] = 0x0175;
                    break;

                case 0x0176:
                    target[limit++] = 0x0177;
                    break;

                case 0x0178:
                    target[limit++] = 0x00FF;
                    break;

                case 0x0179:
                    target[limit++] = 0x017A;
                    break;

                case 0x017B:
                    target[limit++] = 0x017C;
                    break;

                case 0x017D:
                    target[limit++] = 0x017E;
                    break;

                case 0x017F:
                    target[limit++] = 0x0073;
                    break;

                case 0x0181:
                    target[limit++] = 0x0253;
                    break;

                case 0x0182:
                    target[limit++] = 0x0183;
                    break;

                case 0x0184:
                    target[limit++] = 0x0185;
                    break;

                case 0x0186:
                    target[limit++] = 0x0254;
                    break;

                case 0x0187:
                    target[limit++] = 0x0188;
                    break;

                case 0x0189:
                    target[limit++] = 0x0256;
                    break;

                case 0x018A:
                    target[limit++] = 0x0257;
                    break;

                case 0x018B:
                    target[limit++] = 0x018C;
                    break;

                case 0x018E:
                    target[limit++] = 0x01DD;
                    break;

                case 0x018F:
                    target[limit++] = 0x0259;
                    break;

                case 0x0190:
                    target[limit++] = 0x025B;
                    break;

                case 0x0191:
                    target[limit++] = 0x0192;
                    break;

                case 0x0193:
                    target[limit++] = 0x0260;
                    break;

                case 0x0194:
                    target[limit++] = 0x0263;
                    break;

                case 0x0196:
                    target[limit++] = 0x0269;
                    break;

                case 0x0197:
                    target[limit++] = 0x0268;
                    break;

                case 0x0198:
                    target[limit++] = 0x0199;
                    break;

                case 0x019C:
                    target[limit++] = 0x026F;
                    break;

                case 0x019D:
                    target[limit++] = 0x0272;
                    break;

                case 0x019F:
                    target[limit++] = 0x0275;
                    break;

                case 0x01A0:
                    target[limit++] = 0x01A1;
                    break;

                case 0x01A2:
                    target[limit++] = 0x01A3;
                    break;

                case 0x01A4:
                    target[limit++] = 0x01A5;
                    break;

                case 0x01A6:
                    target[limit++] = 0x0280;
                    break;

                case 0x01A7:
                    target[limit++] = 0x01A8;
                    break;

                case 0x01A9:
                    target[limit++] = 0x0283;
                    break;

                case 0x01AC:
                    target[limit++] = 0x01AD;
                    break;

                case 0x01AE:
                    target[limit++] = 0x0288;
                    break;

                case 0x01AF:
                    target[limit++] = 0x01B0;
                    break;

                case 0x01B1:
                    target[limit++] = 0x028A;
                    break;

                case 0x01B2:
                    target[limit++] = 0x028B;
                    break;

                case 0x01B3:
                    target[limit++] = 0x01B4;
                    break;

                case 0x01B5:
                    target[limit++] = 0x01B6;
                    break;

                case 0x01B7:
                    target[limit++] = 0x0292;
                    break;

                case 0x01B8:
                    target[limit++] = 0x01B9;
                    break;

                case 0x01BC:
                    target[limit++] = 0x01BD;
                    break;

                case 0x01C4:
                    target[limit++] = 0x01C6;
                    break;

                case 0x01C5:
                    target[limit++] = 0x01C6;
                    break;

                case 0x01C7:
                    target[limit++] = 0x01C9;
                    break;

                case 0x01C8:
                    target[limit++] = 0x01C9;
                    break;

                case 0x01CA:
                    target[limit++] = 0x01CC;
                    break;

                case 0x01CB:
                    target[limit++] = 0x01CC;
                    break;

                case 0x01CD:
                    target[limit++] = 0x01CE;
                    break;

                case 0x01CF:
                    target[limit++] = 0x01D0;
                    break;

                case 0x01D1:
                    target[limit++] = 0x01D2;
                    break;

                case 0x01D3:
                    target[limit++] = 0x01D4;
                    break;

                case 0x01D5:
                    target[limit++] = 0x01D6;
                    break;

                case 0x01D7:
                    target[limit++] = 0x01D8;
                    break;

                case 0x01D9:
                    target[limit++] = 0x01DA;
                    break;

                case 0x01DB:
                    target[limit++] = 0x01DC;
                    break;

                case 0x01DE:
                    target[limit++] = 0x01DF;
                    break;

                case 0x01E0:
                    target[limit++] = 0x01E1;
                    break;

                case 0x01E2:
                    target[limit++] = 0x01E3;
                    break;

                case 0x01E4:
                    target[limit++] = 0x01E5;
                    break;

                case 0x01E6:
                    target[limit++] = 0x01E7;
                    break;

                case 0x01E8:
                    target[limit++] = 0x01E9;
                    break;

                case 0x01EA:
                    target[limit++] = 0x01EB;
                    break;

                case 0x01EC:
                    target[limit++] = 0x01ED;
                    break;

                case 0x01EE:
                    target[limit++] = 0x01EF;
                    break;

                case 0x01F0:
                    target[limit++] = 0x006A;
                    target[limit++] = 0x030C;
                    break;

                case 0x01F1:
                    target[limit++] = 0x01F3;
                    break;

                case 0x01F2:
                    target[limit++] = 0x01F3;
                    break;

                case 0x01F4:
                    target[limit++] = 0x01F5;
                    break;

                case 0x01F6:
                    target[limit++] = 0x0195;
                    break;

                case 0x01F7:
                    target[limit++] = 0x01BF;
                    break;

                case 0x01F8:
                    target[limit++] = 0x01F9;
                    break;

                case 0x01FA:
                    target[limit++] = 0x01FB;
                    break;

                case 0x01FC:
                    target[limit++] = 0x01FD;
                    break;

                case 0x01FE:
                    target[limit++] = 0x01FF;
                    break;

                case 0x0200:
                    target[limit++] = 0x0201;
                    break;

                case 0x0202:
                    target[limit++] = 0x0203;
                    break;

                case 0x0204:
                    target[limit++] = 0x0205;
                    break;

                case 0x0206:
                    target[limit++] = 0x0207;
                    break;

                case 0x0208:
                    target[limit++] = 0x0209;
                    break;

                case 0x020A:
                    target[limit++] = 0x020B;
                    break;

                case 0x020C:
                    target[limit++] = 0x020D;
                    break;

                case 0x020E:
                    target[limit++] = 0x020F;
                    break;

                case 0x0210:
                    target[limit++] = 0x0211;
                    break;

                case 0x0212:
                    target[limit++] = 0x0213;
                    break;

                case 0x0214:
                    target[limit++] = 0x0215;
                    break;

                case 0x0216:
                    target[limit++] = 0x0217;
                    break;

                case 0x0218:
                    target[limit++] = 0x0219;
                    break;

                case 0x021A:
                    target[limit++] = 0x021B;
                    break;

                case 0x021C:
                    target[limit++] = 0x021D;
                    break;

                case 0x021E:
                    target[limit++] = 0x021F;
                    break;

                case 0x0220:
                    target[limit++] = 0x019E;
                    break;

                case 0x0222:
                    target[limit++] = 0x0223;
                    break;

                case 0x0224:
                    target[limit++] = 0x0225;
                    break;

                case 0x0226:
                    target[limit++] = 0x0227;
                    break;

                case 0x0228:
                    target[limit++] = 0x0229;
                    break;

                case 0x022A:
                    target[limit++] = 0x022B;
                    break;

                case 0x022C:
                    target[limit++] = 0x022D;
                    break;

                case 0x022E:
                    target[limit++] = 0x022F;
                    break;

                case 0x0230:
                    target[limit++] = 0x0231;
                    break;

                case 0x0232:
                    target[limit++] = 0x0233;
                    break;

                case 0x0345:
                    target[limit++] = 0x03B9;
                    break;

                case 0x034F:
                    break;

                case 0x037A:
                    target[limit++] = 0x0020;
                    target[limit++] = 0x03B9;
                    break;

                case 0x0386:
                    target[limit++] = 0x03AC;
                    break;

                case 0x0388:
                    target[limit++] = 0x03AD;
                    break;

                case 0x0389:
                    target[limit++] = 0x03AE;
                    break;

                case 0x038A:
                    target[limit++] = 0x03AF;
                    break;

                case 0x038C:
                    target[limit++] = 0x03CC;
                    break;

                case 0x038E:
                    target[limit++] = 0x03CD;
                    break;

                case 0x038F:
                    target[limit++] = 0x03CE;
                    break;

                case 0x0390:
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0301;
                    break;

                case 0x0391:
                    target[limit++] = 0x03B1;
                    break;

                case 0x0392:
                    target[limit++] = 0x03B2;
                    break;

                case 0x0393:
                    target[limit++] = 0x03B3;
                    break;

                case 0x0394:
                    target[limit++] = 0x03B4;
                    break;

                case 0x0395:
                    target[limit++] = 0x03B5;
                    break;

                case 0x0396:
                    target[limit++] = 0x03B6;
                    break;

                case 0x0397:
                    target[limit++] = 0x03B7;
                    break;

                case 0x0398:
                    target[limit++] = 0x03B8;
                    break;

                case 0x0399:
                    target[limit++] = 0x03B9;
                    break;

                case 0x039A:
                    target[limit++] = 0x03BA;
                    break;

                case 0x039B:
                    target[limit++] = 0x03BB;
                    break;

                case 0x039C:
                    target[limit++] = 0x03BC;
                    break;

                case 0x039D:
                    target[limit++] = 0x03BD;
                    break;

                case 0x039E:
                    target[limit++] = 0x03BE;
                    break;

                case 0x039F:
                    target[limit++] = 0x03BF;
                    break;

                case 0x03A0:
                    target[limit++] = 0x03C0;
                    break;

                case 0x03A1:
                    target[limit++] = 0x03C1;
                    break;

                case 0x03A3:
                    target[limit++] = 0x03C3;
                    break;

                case 0x03A4:
                    target[limit++] = 0x03C4;
                    break;

                case 0x03A5:
                    target[limit++] = 0x03C5;
                    break;

                case 0x03A6:
                    target[limit++] = 0x03C6;
                    break;

                case 0x03A7:
                    target[limit++] = 0x03C7;
                    break;

                case 0x03A8:
                    target[limit++] = 0x03C8;
                    break;

                case 0x03A9:
                    target[limit++] = 0x03C9;
                    break;

                case 0x03AA:
                    target[limit++] = 0x03CA;
                    break;

                case 0x03AB:
                    target[limit++] = 0x03CB;
                    break;

                case 0x03B0:
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0301;
                    break;

                case 0x03C2:
                    target[limit++] = 0x03C3;
                    break;

                case 0x03D0:
                    target[limit++] = 0x03B2;
                    break;

                case 0x03D1:
                    target[limit++] = 0x03B8;
                    break;

                case 0x03D2:
                    target[limit++] = 0x03C5;
                    break;

                case 0x03D3:
                    target[limit++] = 0x03CD;
                    break;

                case 0x03D4:
                    target[limit++] = 0x03CB;
                    break;

                case 0x03D5:
                    target[limit++] = 0x03C6;
                    break;

                case 0x03D6:
                    target[limit++] = 0x03C0;
                    break;

                case 0x03D8:
                    target[limit++] = 0x03D9;
                    break;

                case 0x03DA:
                    target[limit++] = 0x03DB;
                    break;

                case 0x03DC:
                    target[limit++] = 0x03DD;
                    break;

                case 0x03DE:
                    target[limit++] = 0x03DF;
                    break;

                case 0x03E0:
                    target[limit++] = 0x03E1;
                    break;

                case 0x03E2:
                    target[limit++] = 0x03E3;
                    break;

                case 0x03E4:
                    target[limit++] = 0x03E5;
                    break;

                case 0x03E6:
                    target[limit++] = 0x03E7;
                    break;

                case 0x03E8:
                    target[limit++] = 0x03E9;
                    break;

                case 0x03EA:
                    target[limit++] = 0x03EB;
                    break;

                case 0x03EC:
                    target[limit++] = 0x03ED;
                    break;

                case 0x03EE:
                    target[limit++] = 0x03EF;
                    break;

                case 0x03F0:
                    target[limit++] = 0x03BA;
                    break;

                case 0x03F1:
                    target[limit++] = 0x03C1;
                    break;

                case 0x03F2:
                    target[limit++] = 0x03C3;
                    break;

                case 0x03F4:
                    target[limit++] = 0x03B8;
                    break;

                case 0x03F5:
                    target[limit++] = 0x03B5;
                    break;

                case 0x0400:
                    target[limit++] = 0x0450;
                    break;

                case 0x0401:
                    target[limit++] = 0x0451;
                    break;

                case 0x0402:
                    target[limit++] = 0x0452;
                    break;

                case 0x0403:
                    target[limit++] = 0x0453;
                    break;

                case 0x0404:
                    target[limit++] = 0x0454;
                    break;

                case 0x0405:
                    target[limit++] = 0x0455;
                    break;

                case 0x0406:
                    target[limit++] = 0x0456;
                    break;

                case 0x0407:
                    target[limit++] = 0x0457;
                    break;

                case 0x0408:
                    target[limit++] = 0x0458;
                    break;

                case 0x0409:
                    target[limit++] = 0x0459;
                    break;

                case 0x040A:
                    target[limit++] = 0x045A;
                    break;

                case 0x040B:
                    target[limit++] = 0x045B;
                    break;

                case 0x040C:
                    target[limit++] = 0x045C;
                    break;

                case 0x040D:
                    target[limit++] = 0x045D;
                    break;

                case 0x040E:
                    target[limit++] = 0x045E;
                    break;

                case 0x040F:
                    target[limit++] = 0x045F;
                    break;

                case 0x0410:
                    target[limit++] = 0x0430;
                    break;

                case 0x0411:
                    target[limit++] = 0x0431;
                    break;

                case 0x0412:
                    target[limit++] = 0x0432;
                    break;

                case 0x0413:
                    target[limit++] = 0x0433;
                    break;

                case 0x0414:
                    target[limit++] = 0x0434;
                    break;

                case 0x0415:
                    target[limit++] = 0x0435;
                    break;

                case 0x0416:
                    target[limit++] = 0x0436;
                    break;

                case 0x0417:
                    target[limit++] = 0x0437;
                    break;

                case 0x0418:
                    target[limit++] = 0x0438;
                    break;

                case 0x0419:
                    target[limit++] = 0x0439;
                    break;

                case 0x041A:
                    target[limit++] = 0x043A;
                    break;

                case 0x041B:
                    target[limit++] = 0x043B;
                    break;

                case 0x041C:
                    target[limit++] = 0x043C;
                    break;

                case 0x041D:
                    target[limit++] = 0x043D;
                    break;

                case 0x041E:
                    target[limit++] = 0x043E;
                    break;

                case 0x041F:
                    target[limit++] = 0x043F;
                    break;

                case 0x0420:
                    target[limit++] = 0x0440;
                    break;

                case 0x0421:
                    target[limit++] = 0x0441;
                    break;

                case 0x0422:
                    target[limit++] = 0x0442;
                    break;

                case 0x0423:
                    target[limit++] = 0x0443;
                    break;

                case 0x0424:
                    target[limit++] = 0x0444;
                    break;

                case 0x0425:
                    target[limit++] = 0x0445;
                    break;

                case 0x0426:
                    target[limit++] = 0x0446;
                    break;

                case 0x0427:
                    target[limit++] = 0x0447;
                    break;

                case 0x0428:
                    target[limit++] = 0x0448;
                    break;

                case 0x0429:
                    target[limit++] = 0x0449;
                    break;

                case 0x042A:
                    target[limit++] = 0x044A;
                    break;

                case 0x042B:
                    target[limit++] = 0x044B;
                    break;

                case 0x042C:
                    target[limit++] = 0x044C;
                    break;

                case 0x042D:
                    target[limit++] = 0x044D;
                    break;

                case 0x042E:
                    target[limit++] = 0x044E;
                    break;

                case 0x042F:
                    target[limit++] = 0x044F;
                    break;

                case 0x0460:
                    target[limit++] = 0x0461;
                    break;

                case 0x0462:
                    target[limit++] = 0x0463;
                    break;

                case 0x0464:
                    target[limit++] = 0x0465;
                    break;

                case 0x0466:
                    target[limit++] = 0x0467;
                    break;

                case 0x0468:
                    target[limit++] = 0x0469;
                    break;

                case 0x046A:
                    target[limit++] = 0x046B;
                    break;

                case 0x046C:
                    target[limit++] = 0x046D;
                    break;

                case 0x046E:
                    target[limit++] = 0x046F;
                    break;

                case 0x0470:
                    target[limit++] = 0x0471;
                    break;

                case 0x0472:
                    target[limit++] = 0x0473;
                    break;

                case 0x0474:
                    target[limit++] = 0x0475;
                    break;

                case 0x0476:
                    target[limit++] = 0x0477;
                    break;

                case 0x0478:
                    target[limit++] = 0x0479;
                    break;

                case 0x047A:
                    target[limit++] = 0x047B;
                    break;

                case 0x047C:
                    target[limit++] = 0x047D;
                    break;

                case 0x047E:
                    target[limit++] = 0x047F;
                    break;

                case 0x0480:
                    target[limit++] = 0x0481;
                    break;

                case 0x048A:
                    target[limit++] = 0x048B;
                    break;

                case 0x048C:
                    target[limit++] = 0x048D;
                    break;

                case 0x048E:
                    target[limit++] = 0x048F;
                    break;

                case 0x0490:
                    target[limit++] = 0x0491;
                    break;

                case 0x0492:
                    target[limit++] = 0x0493;
                    break;

                case 0x0494:
                    target[limit++] = 0x0495;
                    break;

                case 0x0496:
                    target[limit++] = 0x0497;
                    break;

                case 0x0498:
                    target[limit++] = 0x0499;
                    break;

                case 0x049A:
                    target[limit++] = 0x049B;
                    break;

                case 0x049C:
                    target[limit++] = 0x049D;
                    break;

                case 0x049E:
                    target[limit++] = 0x049F;
                    break;

                case 0x04A0:
                    target[limit++] = 0x04A1;
                    break;

                case 0x04A2:
                    target[limit++] = 0x04A3;
                    break;

                case 0x04A4:
                    target[limit++] = 0x04A5;
                    break;

                case 0x04A6:
                    target[limit++] = 0x04A7;
                    break;

                case 0x04A8:
                    target[limit++] = 0x04A9;
                    break;

                case 0x04AA:
                    target[limit++] = 0x04AB;
                    break;

                case 0x04AC:
                    target[limit++] = 0x04AD;
                    break;

                case 0x04AE:
                    target[limit++] = 0x04AF;
                    break;

                case 0x04B0:
                    target[limit++] = 0x04B1;
                    break;

                case 0x04B2:
                    target[limit++] = 0x04B3;
                    break;

                case 0x04B4:
                    target[limit++] = 0x04B5;
                    break;

                case 0x04B6:
                    target[limit++] = 0x04B7;
                    break;

                case 0x04B8:
                    target[limit++] = 0x04B9;
                    break;

                case 0x04BA:
                    target[limit++] = 0x04BB;
                    break;

                case 0x04BC:
                    target[limit++] = 0x04BD;
                    break;

                case 0x04BE:
                    target[limit++] = 0x04BF;
                    break;

                case 0x04C1:
                    target[limit++] = 0x04C2;
                    break;

                case 0x04C3:
                    target[limit++] = 0x04C4;
                    break;

                case 0x04C5:
                    target[limit++] = 0x04C6;
                    break;

                case 0x04C7:
                    target[limit++] = 0x04C8;
                    break;

                case 0x04C9:
                    target[limit++] = 0x04CA;
                    break;

                case 0x04CB:
                    target[limit++] = 0x04CC;
                    break;

                case 0x04CD:
                    target[limit++] = 0x04CE;
                    break;

                case 0x04D0:
                    target[limit++] = 0x04D1;
                    break;

                case 0x04D2:
                    target[limit++] = 0x04D3;
                    break;

                case 0x04D4:
                    target[limit++] = 0x04D5;
                    break;

                case 0x04D6:
                    target[limit++] = 0x04D7;
                    break;

                case 0x04D8:
                    target[limit++] = 0x04D9;
                    break;

                case 0x04DA:
                    target[limit++] = 0x04DB;
                    break;

                case 0x04DC:
                    target[limit++] = 0x04DD;
                    break;

                case 0x04DE:
                    target[limit++] = 0x04DF;
                    break;

                case 0x04E0:
                    target[limit++] = 0x04E1;
                    break;

                case 0x04E2:
                    target[limit++] = 0x04E3;
                    break;

                case 0x04E4:
                    target[limit++] = 0x04E5;
                    break;

                case 0x04E6:
                    target[limit++] = 0x04E7;
                    break;

                case 0x04E8:
                    target[limit++] = 0x04E9;
                    break;

                case 0x04EA:
                    target[limit++] = 0x04EB;
                    break;

                case 0x04EC:
                    target[limit++] = 0x04ED;
                    break;

                case 0x04EE:
                    target[limit++] = 0x04EF;
                    break;

                case 0x04F0:
                    target[limit++] = 0x04F1;
                    break;

                case 0x04F2:
                    target[limit++] = 0x04F3;
                    break;

                case 0x04F4:
                    target[limit++] = 0x04F5;
                    break;

                case 0x04F8:
                    target[limit++] = 0x04F9;
                    break;

                case 0x0500:
                    target[limit++] = 0x0501;
                    break;

                case 0x0502:
                    target[limit++] = 0x0503;
                    break;

                case 0x0504:
                    target[limit++] = 0x0505;
                    break;

                case 0x0506:
                    target[limit++] = 0x0507;
                    break;

                case 0x0508:
                    target[limit++] = 0x0509;
                    break;

                case 0x050A:
                    target[limit++] = 0x050B;
                    break;

                case 0x050C:
                    target[limit++] = 0x050D;
                    break;

                case 0x050E:
                    target[limit++] = 0x050F;
                    break;

                case 0x0531:
                    target[limit++] = 0x0561;
                    break;

                case 0x0532:
                    target[limit++] = 0x0562;
                    break;

                case 0x0533:
                    target[limit++] = 0x0563;
                    break;

                case 0x0534:
                    target[limit++] = 0x0564;
                    break;

                case 0x0535:
                    target[limit++] = 0x0565;
                    break;

                case 0x0536:
                    target[limit++] = 0x0566;
                    break;

                case 0x0537:
                    target[limit++] = 0x0567;
                    break;

                case 0x0538:
                    target[limit++] = 0x0568;
                    break;

                case 0x0539:
                    target[limit++] = 0x0569;
                    break;

                case 0x053A:
                    target[limit++] = 0x056A;
                    break;

                case 0x053B:
                    target[limit++] = 0x056B;
                    break;

                case 0x053C:
                    target[limit++] = 0x056C;
                    break;

                case 0x053D:
                    target[limit++] = 0x056D;
                    break;

                case 0x053E:
                    target[limit++] = 0x056E;
                    break;

                case 0x053F:
                    target[limit++] = 0x056F;
                    break;

                case 0x0540:
                    target[limit++] = 0x0570;
                    break;

                case 0x0541:
                    target[limit++] = 0x0571;
                    break;

                case 0x0542:
                    target[limit++] = 0x0572;
                    break;

                case 0x0543:
                    target[limit++] = 0x0573;
                    break;

                case 0x0544:
                    target[limit++] = 0x0574;
                    break;

                case 0x0545:
                    target[limit++] = 0x0575;
                    break;

                case 0x0546:
                    target[limit++] = 0x0576;
                    break;

                case 0x0547:
                    target[limit++] = 0x0577;
                    break;

                case 0x0548:
                    target[limit++] = 0x0578;
                    break;

                case 0x0549:
                    target[limit++] = 0x0579;
                    break;

                case 0x054A:
                    target[limit++] = 0x057A;
                    break;

                case 0x054B:
                    target[limit++] = 0x057B;
                    break;

                case 0x054C:
                    target[limit++] = 0x057C;
                    break;

                case 0x054D:
                    target[limit++] = 0x057D;
                    break;

                case 0x054E:
                    target[limit++] = 0x057E;
                    break;

                case 0x054F:
                    target[limit++] = 0x057F;
                    break;

                case 0x0550:
                    target[limit++] = 0x0580;
                    break;

                case 0x0551:
                    target[limit++] = 0x0581;
                    break;

                case 0x0552:
                    target[limit++] = 0x0582;
                    break;

                case 0x0553:
                    target[limit++] = 0x0583;
                    break;

                case 0x0554:
                    target[limit++] = 0x0584;
                    break;

                case 0x0555:
                    target[limit++] = 0x0585;
                    break;

                case 0x0556:
                    target[limit++] = 0x0586;
                    break;

                case 0x0587:
                    target[limit++] = 0x0565;
                    target[limit++] = 0x0582;
                    break;

                case 0x06DD:
                    break;

                case 0x070F:
                    break;

                case 0x1680:
                    target[limit++] = 0x0020;
                    break;

                case 0x1806:
                    break;

                case 0x180B:
                case 0x180C:
                case 0x180D:
                case 0x180E:
                    break;

                case 0x1E00:
                    target[limit++] = 0x1E01;
                    break;

                case 0x1E02:
                    target[limit++] = 0x1E03;
                    break;

                case 0x1E04:
                    target[limit++] = 0x1E05;
                    break;

                case 0x1E06:
                    target[limit++] = 0x1E07;
                    break;

                case 0x1E08:
                    target[limit++] = 0x1E09;
                    break;

                case 0x1E0A:
                    target[limit++] = 0x1E0B;
                    break;

                case 0x1E0C:
                    target[limit++] = 0x1E0D;
                    break;

                case 0x1E0E:
                    target[limit++] = 0x1E0F;
                    break;

                case 0x1E10:
                    target[limit++] = 0x1E11;
                    break;

                case 0x1E12:
                    target[limit++] = 0x1E13;
                    break;

                case 0x1E14:
                    target[limit++] = 0x1E15;
                    break;

                case 0x1E16:
                    target[limit++] = 0x1E17;
                    break;

                case 0x1E18:
                    target[limit++] = 0x1E19;
                    break;

                case 0x1E1A:
                    target[limit++] = 0x1E1B;
                    break;

                case 0x1E1C:
                    target[limit++] = 0x1E1D;
                    break;

                case 0x1E1E:
                    target[limit++] = 0x1E1F;
                    break;

                case 0x1E20:
                    target[limit++] = 0x1E21;
                    break;

                case 0x1E22:
                    target[limit++] = 0x1E23;
                    break;

                case 0x1E24:
                    target[limit++] = 0x1E25;
                    break;

                case 0x1E26:
                    target[limit++] = 0x1E27;
                    break;

                case 0x1E28:
                    target[limit++] = 0x1E29;
                    break;

                case 0x1E2A:
                    target[limit++] = 0x1E2B;
                    break;

                case 0x1E2C:
                    target[limit++] = 0x1E2D;
                    break;

                case 0x1E2E:
                    target[limit++] = 0x1E2F;
                    break;

                case 0x1E30:
                    target[limit++] = 0x1E31;
                    break;

                case 0x1E32:
                    target[limit++] = 0x1E33;
                    break;

                case 0x1E34:
                    target[limit++] = 0x1E35;
                    break;

                case 0x1E36:
                    target[limit++] = 0x1E37;
                    break;

                case 0x1E38:
                    target[limit++] = 0x1E39;
                    break;

                case 0x1E3A:
                    target[limit++] = 0x1E3B;
                    break;

                case 0x1E3C:
                    target[limit++] = 0x1E3D;
                    break;

                case 0x1E3E:
                    target[limit++] = 0x1E3F;
                    break;

                case 0x1E40:
                    target[limit++] = 0x1E41;
                    break;

                case 0x1E42:
                    target[limit++] = 0x1E43;
                    break;

                case 0x1E44:
                    target[limit++] = 0x1E45;
                    break;

                case 0x1E46:
                    target[limit++] = 0x1E47;
                    break;

                case 0x1E48:
                    target[limit++] = 0x1E49;
                    break;

                case 0x1E4A:
                    target[limit++] = 0x1E4B;
                    break;

                case 0x1E4C:
                    target[limit++] = 0x1E4D;
                    break;

                case 0x1E4E:
                    target[limit++] = 0x1E4F;
                    break;

                case 0x1E50:
                    target[limit++] = 0x1E51;
                    break;

                case 0x1E52:
                    target[limit++] = 0x1E53;
                    break;

                case 0x1E54:
                    target[limit++] = 0x1E55;
                    break;

                case 0x1E56:
                    target[limit++] = 0x1E57;
                    break;

                case 0x1E58:
                    target[limit++] = 0x1E59;
                    break;

                case 0x1E5A:
                    target[limit++] = 0x1E5B;
                    break;

                case 0x1E5C:
                    target[limit++] = 0x1E5D;
                    break;

                case 0x1E5E:
                    target[limit++] = 0x1E5F;
                    break;

                case 0x1E60:
                    target[limit++] = 0x1E61;
                    break;

                case 0x1E62:
                    target[limit++] = 0x1E63;
                    break;

                case 0x1E64:
                    target[limit++] = 0x1E65;
                    break;

                case 0x1E66:
                    target[limit++] = 0x1E67;
                    break;

                case 0x1E68:
                    target[limit++] = 0x1E69;
                    break;

                case 0x1E6A:
                    target[limit++] = 0x1E6B;
                    break;

                case 0x1E6C:
                    target[limit++] = 0x1E6D;
                    break;

                case 0x1E6E:
                    target[limit++] = 0x1E6F;
                    break;

                case 0x1E70:
                    target[limit++] = 0x1E71;
                    break;

                case 0x1E72:
                    target[limit++] = 0x1E73;
                    break;

                case 0x1E74:
                    target[limit++] = 0x1E75;
                    break;

                case 0x1E76:
                    target[limit++] = 0x1E77;
                    break;

                case 0x1E78:
                    target[limit++] = 0x1E79;
                    break;

                case 0x1E7A:
                    target[limit++] = 0x1E7B;
                    break;

                case 0x1E7C:
                    target[limit++] = 0x1E7D;
                    break;

                case 0x1E7E:
                    target[limit++] = 0x1E7F;
                    break;

                case 0x1E80:
                    target[limit++] = 0x1E81;
                    break;

                case 0x1E82:
                    target[limit++] = 0x1E83;
                    break;

                case 0x1E84:
                    target[limit++] = 0x1E85;
                    break;

                case 0x1E86:
                    target[limit++] = 0x1E87;
                    break;

                case 0x1E88:
                    target[limit++] = 0x1E89;
                    break;

                case 0x1E8A:
                    target[limit++] = 0x1E8B;
                    break;

                case 0x1E8C:
                    target[limit++] = 0x1E8D;
                    break;

                case 0x1E8E:
                    target[limit++] = 0x1E8F;
                    break;

                case 0x1E90:
                    target[limit++] = 0x1E91;
                    break;

                case 0x1E92:
                    target[limit++] = 0x1E93;
                    break;

                case 0x1E94:
                    target[limit++] = 0x1E95;
                    break;

                case 0x1E96:
                    target[limit++] = 0x0068;
                    target[limit++] = 0x0331;
                    break;

                case 0x1E97:
                    target[limit++] = 0x0074;
                    target[limit++] = 0x0308;
                    break;

                case 0x1E98:
                    target[limit++] = 0x0077;
                    target[limit++] = 0x030A;
                    break;

                case 0x1E99:
                    target[limit++] = 0x0079;
                    target[limit++] = 0x030A;
                    break;

                case 0x1E9A:
                    target[limit++] = 0x0061;
                    target[limit++] = 0x02BE;
                    break;

                case 0x1E9B:
                    target[limit++] = 0x1E61;
                    break;

                case 0x1EA0:
                    target[limit++] = 0x1EA1;
                    break;

                case 0x1EA2:
                    target[limit++] = 0x1EA3;
                    break;

                case 0x1EA4:
                    target[limit++] = 0x1EA5;
                    break;

                case 0x1EA6:
                    target[limit++] = 0x1EA7;
                    break;

                case 0x1EA8:
                    target[limit++] = 0x1EA9;
                    break;

                case 0x1EAA:
                    target[limit++] = 0x1EAB;
                    break;

                case 0x1EAC:
                    target[limit++] = 0x1EAD;
                    break;

                case 0x1EAE:
                    target[limit++] = 0x1EAF;
                    break;

                case 0x1EB0:
                    target[limit++] = 0x1EB1;
                    break;

                case 0x1EB2:
                    target[limit++] = 0x1EB3;
                    break;

                case 0x1EB4:
                    target[limit++] = 0x1EB5;
                    break;

                case 0x1EB6:
                    target[limit++] = 0x1EB7;
                    break;

                case 0x1EB8:
                    target[limit++] = 0x1EB9;
                    break;

                case 0x1EBA:
                    target[limit++] = 0x1EBB;
                    break;

                case 0x1EBC:
                    target[limit++] = 0x1EBD;
                    break;

                case 0x1EBE:
                    target[limit++] = 0x1EBF;
                    break;

                case 0x1EC0:
                    target[limit++] = 0x1EC1;
                    break;

                case 0x1EC2:
                    target[limit++] = 0x1EC3;
                    break;

                case 0x1EC4:
                    target[limit++] = 0x1EC5;
                    break;

                case 0x1EC6:
                    target[limit++] = 0x1EC7;
                    break;

                case 0x1EC8:
                    target[limit++] = 0x1EC9;
                    break;

                case 0x1ECA:
                    target[limit++] = 0x1ECB;
                    break;

                case 0x1ECC:
                    target[limit++] = 0x1ECD;
                    break;

                case 0x1ECE:
                    target[limit++] = 0x1ECF;
                    break;

                case 0x1ED0:
                    target[limit++] = 0x1ED1;
                    break;

                case 0x1ED2:
                    target[limit++] = 0x1ED3;
                    break;

                case 0x1ED4:
                    target[limit++] = 0x1ED5;
                    break;

                case 0x1ED6:
                    target[limit++] = 0x1ED7;
                    break;

                case 0x1ED8:
                    target[limit++] = 0x1ED9;
                    break;

                case 0x1EDA:
                    target[limit++] = 0x1EDB;
                    break;

                case 0x1EDC:
                    target[limit++] = 0x1EDD;
                    break;

                case 0x1EDE:
                    target[limit++] = 0x1EDF;
                    break;

                case 0x1EE0:
                    target[limit++] = 0x1EE1;
                    break;

                case 0x1EE2:
                    target[limit++] = 0x1EE3;
                    break;

                case 0x1EE4:
                    target[limit++] = 0x1EE5;
                    break;

                case 0x1EE6:
                    target[limit++] = 0x1EE7;
                    break;

                case 0x1EE8:
                    target[limit++] = 0x1EE9;
                    break;

                case 0x1EEA:
                    target[limit++] = 0x1EEB;
                    break;

                case 0x1EEC:
                    target[limit++] = 0x1EED;
                    break;

                case 0x1EEE:
                    target[limit++] = 0x1EEF;
                    break;

                case 0x1EF0:
                    target[limit++] = 0x1EF1;
                    break;

                case 0x1EF2:
                    target[limit++] = 0x1EF3;
                    break;

                case 0x1EF4:
                    target[limit++] = 0x1EF5;
                    break;

                case 0x1EF6:
                    target[limit++] = 0x1EF7;
                    break;

                case 0x1EF8:
                    target[limit++] = 0x1EF9;
                    break;

                case 0x1F08:
                    target[limit++] = 0x1F00;
                    break;

                case 0x1F09:
                    target[limit++] = 0x1F01;
                    break;

                case 0x1F0A:
                    target[limit++] = 0x1F02;
                    break;

                case 0x1F0B:
                    target[limit++] = 0x1F03;
                    break;

                case 0x1F0C:
                    target[limit++] = 0x1F04;
                    break;

                case 0x1F0D:
                    target[limit++] = 0x1F05;
                    break;

                case 0x1F0E:
                    target[limit++] = 0x1F06;
                    break;

                case 0x1F0F:
                    target[limit++] = 0x1F07;
                    break;

                case 0x1F18:
                    target[limit++] = 0x1F10;
                    break;

                case 0x1F19:
                    target[limit++] = 0x1F11;
                    break;

                case 0x1F1A:
                    target[limit++] = 0x1F12;
                    break;

                case 0x1F1B:
                    target[limit++] = 0x1F13;
                    break;

                case 0x1F1C:
                    target[limit++] = 0x1F14;
                    break;

                case 0x1F1D:
                    target[limit++] = 0x1F15;
                    break;

                case 0x1F28:
                    target[limit++] = 0x1F20;
                    break;

                case 0x1F29:
                    target[limit++] = 0x1F21;
                    break;

                case 0x1F2A:
                    target[limit++] = 0x1F22;
                    break;

                case 0x1F2B:
                    target[limit++] = 0x1F23;
                    break;

                case 0x1F2C:
                    target[limit++] = 0x1F24;
                    break;

                case 0x1F2D:
                    target[limit++] = 0x1F25;
                    break;

                case 0x1F2E:
                    target[limit++] = 0x1F26;
                    break;

                case 0x1F2F:
                    target[limit++] = 0x1F27;
                    break;

                case 0x1F38:
                    target[limit++] = 0x1F30;
                    break;

                case 0x1F39:
                    target[limit++] = 0x1F31;
                    break;

                case 0x1F3A:
                    target[limit++] = 0x1F32;
                    break;

                case 0x1F3B:
                    target[limit++] = 0x1F33;
                    break;

                case 0x1F3C:
                    target[limit++] = 0x1F34;
                    break;

                case 0x1F3D:
                    target[limit++] = 0x1F35;
                    break;

                case 0x1F3E:
                    target[limit++] = 0x1F36;
                    break;

                case 0x1F3F:
                    target[limit++] = 0x1F37;
                    break;

                case 0x1F48:
                    target[limit++] = 0x1F40;
                    break;

                case 0x1F49:
                    target[limit++] = 0x1F41;
                    break;

                case 0x1F4A:
                    target[limit++] = 0x1F42;
                    break;

                case 0x1F4B:
                    target[limit++] = 0x1F43;
                    break;

                case 0x1F4C:
                    target[limit++] = 0x1F44;
                    break;

                case 0x1F4D:
                    target[limit++] = 0x1F45;
                    break;

                case 0x1F50:
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0313;
                    break;

                case 0x1F52:
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0313;
                    target[limit++] = 0x0300;
                    break;

                case 0x1F54:
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0313;
                    target[limit++] = 0x0301;
                    break;

                case 0x1F56:
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0313;
                    target[limit++] = 0x0342;
                    break;

                case 0x1F59:
                    target[limit++] = 0x1F51;
                    break;

                case 0x1F5B:
                    target[limit++] = 0x1F53;
                    break;

                case 0x1F5D:
                    target[limit++] = 0x1F55;
                    break;

                case 0x1F5F:
                    target[limit++] = 0x1F57;
                    break;

                case 0x1F68:
                    target[limit++] = 0x1F60;
                    break;

                case 0x1F69:
                    target[limit++] = 0x1F61;
                    break;

                case 0x1F6A:
                    target[limit++] = 0x1F62;
                    break;

                case 0x1F6B:
                    target[limit++] = 0x1F63;
                    break;

                case 0x1F6C:
                    target[limit++] = 0x1F64;
                    break;

                case 0x1F6D:
                    target[limit++] = 0x1F65;
                    break;

                case 0x1F6E:
                    target[limit++] = 0x1F66;
                    break;

                case 0x1F6F:
                    target[limit++] = 0x1F67;
                    break;

                case 0x1F80:
                    target[limit++] = 0x1F00;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F81:
                    target[limit++] = 0x1F01;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F82:
                    target[limit++] = 0x1F02;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F83:
                    target[limit++] = 0x1F03;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F84:
                    target[limit++] = 0x1F04;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F85:
                    target[limit++] = 0x1F05;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F86:
                    target[limit++] = 0x1F06;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F87:
                    target[limit++] = 0x1F07;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F88:
                    target[limit++] = 0x1F00;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F89:
                    target[limit++] = 0x1F01;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F8A:
                    target[limit++] = 0x1F02;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F8B:
                    target[limit++] = 0x1F03;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F8C:
                    target[limit++] = 0x1F04;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F8D:
                    target[limit++] = 0x1F05;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F8E:
                    target[limit++] = 0x1F06;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F8F:
                    target[limit++] = 0x1F07;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F90:
                    target[limit++] = 0x1F20;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F91:
                    target[limit++] = 0x1F21;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F92:
                    target[limit++] = 0x1F22;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F93:
                    target[limit++] = 0x1F23;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F94:
                    target[limit++] = 0x1F24;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F95:
                    target[limit++] = 0x1F25;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F96:
                    target[limit++] = 0x1F26;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F97:
                    target[limit++] = 0x1F27;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F98:
                    target[limit++] = 0x1F20;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F99:
                    target[limit++] = 0x1F21;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F9A:
                    target[limit++] = 0x1F22;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F9B:
                    target[limit++] = 0x1F23;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F9C:
                    target[limit++] = 0x1F24;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F9D:
                    target[limit++] = 0x1F25;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F9E:
                    target[limit++] = 0x1F26;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F9F:
                    target[limit++] = 0x1F27;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FA0:
                    target[limit++] = 0x1F60;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FA1:
                    target[limit++] = 0x1F61;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FA2:
                    target[limit++] = 0x1F62;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FA3:
                    target[limit++] = 0x1F63;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FA4:
                    target[limit++] = 0x1F64;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FA5:
                    target[limit++] = 0x1F65;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FA6:
                    target[limit++] = 0x1F66;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FA7:
                    target[limit++] = 0x1F67;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FA8:
                    target[limit++] = 0x1F60;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FA9:
                    target[limit++] = 0x1F61;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FAA:
                    target[limit++] = 0x1F62;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FAB:
                    target[limit++] = 0x1F63;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FAC:
                    target[limit++] = 0x1F64;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FAD:
                    target[limit++] = 0x1F65;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FAE:
                    target[limit++] = 0x1F66;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FAF:
                    target[limit++] = 0x1F67;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FB2:
                    target[limit++] = 0x1F70;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FB3:
                    target[limit++] = 0x03B1;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FB4:
                    target[limit++] = 0x03AC;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FB6:
                    target[limit++] = 0x03B1;
                    target[limit++] = 0x0342;
                    break;

                case 0x1FB7:
                    target[limit++] = 0x03B1;
                    target[limit++] = 0x0342;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FB8:
                    target[limit++] = 0x1FB0;
                    break;

                case 0x1FB9:
                    target[limit++] = 0x1FB1;
                    break;

                case 0x1FBA:
                    target[limit++] = 0x1F70;
                    break;

                case 0x1FBB:
                    target[limit++] = 0x1F71;
                    break;

                case 0x1FBC:
                    target[limit++] = 0x03B1;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FBE:
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FC2:
                    target[limit++] = 0x1F74;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FC3:
                    target[limit++] = 0x03B7;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FC4:
                    target[limit++] = 0x03AE;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FC6:
                    target[limit++] = 0x03B7;
                    target[limit++] = 0x0342;
                    break;

                case 0x1FC7:
                    target[limit++] = 0x03B7;
                    target[limit++] = 0x0342;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FC8:
                    target[limit++] = 0x1F72;
                    break;

                case 0x1FC9:
                    target[limit++] = 0x1F73;
                    break;

                case 0x1FCA:
                    target[limit++] = 0x1F74;
                    break;

                case 0x1FCB:
                    target[limit++] = 0x1F75;
                    break;

                case 0x1FCC:
                    target[limit++] = 0x03B7;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FD2:
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0300;
                    break;

                case 0x1FD3:
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0301;
                    break;

                case 0x1FD6:
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0342;
                    break;

                case 0x1FD7:
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0342;
                    break;

                case 0x1FD8:
                    target[limit++] = 0x1FD0;
                    break;

                case 0x1FD9:
                    target[limit++] = 0x1FD1;
                    break;

                case 0x1FDA:
                    target[limit++] = 0x1F76;
                    break;

                case 0x1FDB:
                    target[limit++] = 0x1F77;
                    break;

                case 0x1FE2:
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0300;
                    break;

                case 0x1FE3:
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0301;
                    break;

                case 0x1FE4:
                    target[limit++] = 0x03C1;
                    target[limit++] = 0x0313;
                    break;

                case 0x1FE6:
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0342;
                    break;

                case 0x1FE7:
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0342;
                    break;

                case 0x1FE8:
                    target[limit++] = 0x1FE0;
                    break;

                case 0x1FE9:
                    target[limit++] = 0x1FE1;
                    break;

                case 0x1FEA:
                    target[limit++] = 0x1F7A;
                    break;

                case 0x1FEB:
                    target[limit++] = 0x1F7B;
                    break;

                case 0x1FEC:
                    target[limit++] = 0x1FE5;
                    break;

                case 0x1FF2:
                    target[limit++] = 0x1F7C;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FF3:
                    target[limit++] = 0x03C9;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FF4:
                    target[limit++] = 0x03CE;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FF6:
                    target[limit++] = 0x03C9;
                    target[limit++] = 0x0342;
                    break;

                case 0x1FF7:
                    target[limit++] = 0x03C9;
                    target[limit++] = 0x0342;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FF8:
                    target[limit++] = 0x1F78;
                    break;

                case 0x1FF9:
                    target[limit++] = 0x1F79;
                    break;

                case 0x1FFA:
                    target[limit++] = 0x1F7C;
                    break;

                case 0x1FFB:
                    target[limit++] = 0x1F7D;
                    break;

                case 0x1FFC:
                    target[limit++] = 0x03C9;
                    target[limit++] = 0x03B9;
                    break;

                case 0x2000:
                case 0x2001:
                case 0x2002:
                case 0x2003:
                case 0x2004:
                case 0x2005:
                case 0x2006:
                case 0x2007:
                case 0x2008:
                case 0x2009:
                case 0x200A:
                    target[limit++] = 0x0020;
                    break;

                case 0x200B:
                case 0x200C:
                case 0x200D:
                case 0x200E:
                case 0x200F:
                    break;

                case 0x2028:
                case 0x2029:
                    target[limit++] = 0x0020;
                    break;

                case 0x202A:
                case 0x202B:
                case 0x202C:
                case 0x202D:
                case 0x202E:
                    break;

                case 0x202F:
                    target[limit++] = 0x0020;
                    break;

                case 0x205F:
                    target[limit++] = 0x0020;
                    break;

                case 0x2060:
                case 0x2061:
                case 0x2062:
                case 0x2063:
                    break;

                case 0x206A:
                case 0x206B:
                case 0x206C:
                case 0x206D:
                case 0x206E:
                case 0x206F:
                    break;

                case 0x20A8:
                    target[limit++] = 0x0072;
                    target[limit++] = 0x0073;
                    break;

                case 0x2102:
                    target[limit++] = 0x0063;
                    break;

                case 0x2103:
                    target[limit++] = 0x00B0;
                    target[limit++] = 0x0063;
                    break;

                case 0x2107:
                    target[limit++] = 0x025B;
                    break;

                case 0x2109:
                    target[limit++] = 0x00B0;
                    target[limit++] = 0x0066;
                    break;

                case 0x210B:
                    target[limit++] = 0x0068;
                    break;

                case 0x210C:
                    target[limit++] = 0x0068;
                    break;

                case 0x210D:
                    target[limit++] = 0x0068;
                    break;

                case 0x2110:
                    target[limit++] = 0x0069;
                    break;

                case 0x2111:
                    target[limit++] = 0x0069;
                    break;

                case 0x2112:
                    target[limit++] = 0x006C;
                    break;

                case 0x2115:
                    target[limit++] = 0x006E;
                    break;

                case 0x2116:
                    target[limit++] = 0x006E;
                    target[limit++] = 0x006F;
                    break;

                case 0x2119:
                    target[limit++] = 0x0070;
                    break;

                case 0x211A:
                    target[limit++] = 0x0071;
                    break;

                case 0x211B:
                    target[limit++] = 0x0072;
                    break;

                case 0x211C:
                    target[limit++] = 0x0072;
                    break;

                case 0x211D:
                    target[limit++] = 0x0072;
                    break;

                case 0x2120:
                    target[limit++] = 0x0073;
                    target[limit++] = 0x006D;
                    break;

                case 0x2121:
                    target[limit++] = 0x0074;
                    target[limit++] = 0x0065;
                    target[limit++] = 0x006C;
                    break;

                case 0x2122:
                    target[limit++] = 0x0074;
                    target[limit++] = 0x006D;
                    break;

                case 0x2124:
                    target[limit++] = 0x007A;
                    break;

                case 0x2126:
                    target[limit++] = 0x03C9;
                    break;

                case 0x2128:
                    target[limit++] = 0x007A;
                    break;

                case 0x212A:
                    target[limit++] = 0x006B;
                    break;

                case 0x212B:
                    target[limit++] = 0x00E5;
                    break;

                case 0x212C:
                    target[limit++] = 0x0062;
                    break;

                case 0x212D:
                    target[limit++] = 0x0063;
                    break;

                case 0x2130:
                    target[limit++] = 0x0065;
                    break;

                case 0x2131:
                    target[limit++] = 0x0066;
                    break;

                case 0x2133:
                    target[limit++] = 0x006D;
                    break;

                case 0x213E:
                    target[limit++] = 0x03B3;
                    break;

                case 0x213F:
                    target[limit++] = 0x03C0;
                    break;

                case 0x2145:
                    target[limit++] = 0x0064;
                    break;

                case 0x2160:
                    target[limit++] = 0x2170;
                    break;

                case 0x2161:
                    target[limit++] = 0x2171;
                    break;

                case 0x2162:
                    target[limit++] = 0x2172;
                    break;

                case 0x2163:
                    target[limit++] = 0x2173;
                    break;

                case 0x2164:
                    target[limit++] = 0x2174;
                    break;

                case 0x2165:
                    target[limit++] = 0x2175;
                    break;

                case 0x2166:
                    target[limit++] = 0x2176;
                    break;

                case 0x2167:
                    target[limit++] = 0x2177;
                    break;

                case 0x2168:
                    target[limit++] = 0x2178;
                    break;

                case 0x2169:
                    target[limit++] = 0x2179;
                    break;

                case 0x216A:
                    target[limit++] = 0x217A;
                    break;

                case 0x216B:
                    target[limit++] = 0x217B;
                    break;

                case 0x216C:
                    target[limit++] = 0x217C;
                    break;

                case 0x216D:
                    target[limit++] = 0x217D;
                    break;

                case 0x216E:
                    target[limit++] = 0x217E;
                    break;

                case 0x216F:
                    target[limit++] = 0x217F;
                    break;

                case 0x24B6:
                    target[limit++] = 0x24D0;
                    break;

                case 0x24B7:
                    target[limit++] = 0x24D1;
                    break;

                case 0x24B8:
                    target[limit++] = 0x24D2;
                    break;

                case 0x24B9:
                    target[limit++] = 0x24D3;
                    break;

                case 0x24BA:
                    target[limit++] = 0x24D4;
                    break;

                case 0x24BB:
                    target[limit++] = 0x24D5;
                    break;

                case 0x24BC:
                    target[limit++] = 0x24D6;
                    break;

                case 0x24BD:
                    target[limit++] = 0x24D7;
                    break;

                case 0x24BE:
                    target[limit++] = 0x24D8;
                    break;

                case 0x24BF:
                    target[limit++] = 0x24D9;
                    break;

                case 0x24C0:
                    target[limit++] = 0x24DA;
                    break;

                case 0x24C1:
                    target[limit++] = 0x24DB;
                    break;

                case 0x24C2:
                    target[limit++] = 0x24DC;
                    break;

                case 0x24C3:
                    target[limit++] = 0x24DD;
                    break;

                case 0x24C4:
                    target[limit++] = 0x24DE;
                    break;

                case 0x24C5:
                    target[limit++] = 0x24DF;
                    break;

                case 0x24C6:
                    target[limit++] = 0x24E0;
                    break;

                case 0x24C7:
                    target[limit++] = 0x24E1;
                    break;

                case 0x24C8:
                    target[limit++] = 0x24E2;
                    break;

                case 0x24C9:
                    target[limit++] = 0x24E3;
                    break;

                case 0x24CA:
                    target[limit++] = 0x24E4;
                    break;

                case 0x24CB:
                    target[limit++] = 0x24E5;
                    break;

                case 0x24CC:
                    target[limit++] = 0x24E6;
                    break;

                case 0x24CD:
                    target[limit++] = 0x24E7;
                    break;

                case 0x24CE:
                    target[limit++] = 0x24E8;
                    break;

                case 0x24CF:
                    target[limit++] = 0x24E9;
                    break;

                case 0x3000:
                    target[limit++] = 0x0020;
                    break;

                case 0x3371:
                    target[limit++] = 0x0068;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;

                case 0x3373:
                    target[limit++] = 0x0061;
                    target[limit++] = 0x0075;
                    break;

                case 0x3375:
                    target[limit++] = 0x006F;
                    target[limit++] = 0x0076;
                    break;

                case 0x3380:
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;

                case 0x3381:
                    target[limit++] = 0x006E;
                    target[limit++] = 0x0061;
                    break;

                case 0x3382:
                    target[limit++] = 0x03BC;
                    target[limit++] = 0x0061;
                    break;

                case 0x3383:
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0061;
                    break;

                case 0x3384:
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0061;
                    break;

                case 0x3385:
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0062;
                    break;

                case 0x3386:
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0062;
                    break;

                case 0x3387:
                    target[limit++] = 0x0067;
                    target[limit++] = 0x0062;
                    break;

                case 0x338A:
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0066;
                    break;

                case 0x338B:
                    target[limit++] = 0x006E;
                    target[limit++] = 0x0066;
                    break;

                case 0x338C:
                    target[limit++] = 0x03BC;
                    target[limit++] = 0x0066;
                    break;

                case 0x3390:
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;

                case 0x3391:
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;

                case 0x3392:
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;

                case 0x3393:
                    target[limit++] = 0x0067;
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;

                case 0x3394:
                    target[limit++] = 0x0074;
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;

                case 0x33A9:
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;

                case 0x33AA:
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;

                case 0x33AB:
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;

                case 0x33AC:
                    target[limit++] = 0x0067;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;

                case 0x33B4:
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0076;
                    break;

                case 0x33B5:
                    target[limit++] = 0x006E;
                    target[limit++] = 0x0076;
                    break;

                case 0x33B6:
                    target[limit++] = 0x03BC;
                    target[limit++] = 0x0076;
                    break;

                case 0x33B7:
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0076;
                    break;

                case 0x33B8:
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0076;
                    break;

                case 0x33B9:
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0076;
                    break;

                case 0x33BA:
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0077;
                    break;

                case 0x33BB:
                    target[limit++] = 0x006E;
                    target[limit++] = 0x0077;
                    break;

                case 0x33BC:
                    target[limit++] = 0x03BC;
                    target[limit++] = 0x0077;
                    break;

                case 0x33BD:
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0077;
                    break;

                case 0x33BE:
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0077;
                    break;

                case 0x33BF:
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0077;
                    break;

                case 0x33C0:
                    target[limit++] = 0x006B;
                    target[limit++] = 0x03C9;
                    break;

                case 0x33C1:
                    target[limit++] = 0x006D;
                    target[limit++] = 0x03C9;
                    break;

                case 0x33C3:
                    target[limit++] = 0x0062;
                    target[limit++] = 0x0071;
                    break;

                case 0x33C6:
                    target[limit++] = 0x0063;
                    target[limit++] = 0x2215;
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0067;
                    break;

                case 0x33C7:
                    target[limit++] = 0x0063;
                    target[limit++] = 0x006F;
                    target[limit++] = 0x002E;
                    break;

                case 0x33C8:
                    target[limit++] = 0x0064;
                    target[limit++] = 0x0062;
                    break;

                case 0x33C9:
                    target[limit++] = 0x0067;
                    target[limit++] = 0x0079;
                    break;

                case 0x33CB:
                    target[limit++] = 0x0068;
                    target[limit++] = 0x0070;
                    break;

                case 0x33CD:
                    target[limit++] = 0x006B;
                    target[limit++] = 0x006B;
                    break;

                case 0x33CE:
                    target[limit++] = 0x006B;
                    target[limit++] = 0x006D;
                    break;

                case 0x33D7:
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0068;
                    break;

                case 0x33D9:
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x006D;
                    break;

                case 0x33DA:
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0072;
                    break;

                case 0x33DC:
                    target[limit++] = 0x0073;
                    target[limit++] = 0x0076;
                    break;

                case 0x33DD:
                    target[limit++] = 0x0077;
                    target[limit++] = 0x0062;
                    break;

                case 0xFB00:
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0066;
                    break;

                case 0xFB01:
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0069;
                    break;

                case 0xFB02:
                    target[limit++] = 0x0066;
                    target[limit++] = 0x006C;
                    break;

                case 0xFB03:
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0069;
                    break;

                case 0xFB04:
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0066;
                    target[limit++] = 0x006C;
                    break;

                case 0xFB05:
                    target[limit++] = 0x0073;
                    target[limit++] = 0x0074;
                    break;

                case 0xFB06:
                    target[limit++] = 0x0073;
                    target[limit++] = 0x0074;
                    break;

                case 0xFB13:
                    target[limit++] = 0x0574;
                    target[limit++] = 0x0576;
                    break;

                case 0xFB14:
                    target[limit++] = 0x0574;
                    target[limit++] = 0x0565;
                    break;

                case 0xFB15:
                    target[limit++] = 0x0574;
                    target[limit++] = 0x056B;
                    break;

                case 0xFB16:
                    target[limit++] = 0x057E;
                    target[limit++] = 0x0576;
                    break;

                case 0xFB17:
                    target[limit++] = 0x0574;
                    target[limit++] = 0x056D;
                    break;

                case 0xFE00:
                case 0xFE01:
                case 0xFE02:
                case 0xFE03:
                case 0xFE04:
                case 0xFE05:
                case 0xFE06:
                case 0xFE07:
                case 0xFE08:
                case 0xFE09:
                case 0xFE0A:
                case 0xFE0B:
                case 0xFE0C:
                case 0xFE0D:
                case 0xFE0E:
                case 0xFE0F:
                    break;

                case 0xFEFF:
                    break;

                case 0xFF21:
                    target[limit++] = 0xFF41;
                    break;

                case 0xFF22:
                    target[limit++] = 0xFF42;
                    break;

                case 0xFF23:
                    target[limit++] = 0xFF43;
                    break;

                case 0xFF24:
                    target[limit++] = 0xFF44;
                    break;

                case 0xFF25:
                    target[limit++] = 0xFF45;
                    break;

                case 0xFF26:
                    target[limit++] = 0xFF46;
                    break;

                case 0xFF27:
                    target[limit++] = 0xFF47;
                    break;

                case 0xFF28:
                    target[limit++] = 0xFF48;
                    break;

                case 0xFF29:
                    target[limit++] = 0xFF49;
                    break;

                case 0xFF2A:
                    target[limit++] = 0xFF4A;
                    break;

                case 0xFF2B:
                    target[limit++] = 0xFF4B;
                    break;

                case 0xFF2C:
                    target[limit++] = 0xFF4C;
                    break;

                case 0xFF2D:
                    target[limit++] = 0xFF4D;
                    break;

                case 0xFF2E:
                    target[limit++] = 0xFF4E;
                    break;

                case 0xFF2F:
                    target[limit++] = 0xFF4F;
                    break;

                case 0xFF30:
                    target[limit++] = 0xFF50;
                    break;

                case 0xFF31:
                    target[limit++] = 0xFF51;
                    break;

                case 0xFF32:
                    target[limit++] = 0xFF52;
                    break;

                case 0xFF33:
                    target[limit++] = 0xFF53;
                    break;

                case 0xFF34:
                    target[limit++] = 0xFF54;
                    break;

                case 0xFF35:
                    target[limit++] = 0xFF55;
                    break;

                case 0xFF36:
                    target[limit++] = 0xFF56;
                    break;

                case 0xFF37:
                    target[limit++] = 0xFF57;
                    break;

                case 0xFF38:
                    target[limit++] = 0xFF58;
                    break;

                case 0xFF39:
                    target[limit++] = 0xFF59;
                    break;

                case 0xFF3A:
                    target[limit++] = 0xFF5A;
                    break;

                case 0xFFF9:
                case 0xFFFA:
                case 0xFFFB:
                case 0xFFFC:
                    break;

                default:
                    // First, eliminate surrogates, and replace them by FFFD char
                    if ( ( c >= 0xD800 ) && ( c <= 0xDFFF ) )
                    {
                        target[limit++] = ( char ) 0xFFFD;
                        break;
                    }

                    target[limit++] = c;
                    break;
            }
        }

        return limit;
    }


    /**
     * 
     * Prohibit characters described in RFC 4518 :
     *  - Table A.1 of RFC 3454
     *  - Table C.3 of RFC 3454
     *  - Table C.4 of RFC 3454
     *  - Table C.5 of RFC 3454
     *  - Table C.8 of RFC 3454
     *  - character U-FFFD
     *
     * @param c The char to analyze
     * @throws InvalidCharacterException If any character is prohibited
     */
    private static void checkProhibited( char c ) throws InvalidCharacterException
    {
        // Shortcut chars above 0x0221
        if ( c < 0x221 )
        {
            return;
        }

        // RFC 3454, Table A.1
        switch ( c )
        {
            case 0x0221:
            case 0x038B:
            case 0x038D:
            case 0x03A2:
            case 0x03CF:
            case 0x0487:
            case 0x04CF:
            case 0x0560:
            case 0x0588:
            case 0x05A2:
            case 0x05BA:
            case 0x0620:
            case 0x06FF:
            case 0x070E:
            case 0x0904:
            case 0x0984:
            case 0x09A9:
            case 0x09B1:
            case 0x09BD:
            case 0x09DE:
            case 0x0A29:
            case 0x0A31:
            case 0x0A34:
            case 0x0A37:
            case 0x0A3D:
            case 0x0A5D:
            case 0x0A84:
            case 0x0A8C:
            case 0x0A8E:
            case 0x0A92:
            case 0x0AA9:
            case 0x0AB1:
            case 0x0AB4:
            case 0x0AC6:
            case 0x0ACA:
            case 0x0B04:
            case 0x0B29:
            case 0x0B31:
            case 0x0B5E:
            case 0x0B84:
            case 0x0B91:
            case 0x0B9B:
            case 0x0B9D:
            case 0x0BB6:
            case 0x0BC9:
            case 0x0C04:
            case 0x0C0D:
            case 0x0C11:
            case 0x0C29:
            case 0x0C34:
            case 0x0C45:
            case 0x0C49:
            case 0x0C84:
            case 0x0C8D:
            case 0x0C91:
            case 0x0CA9:
            case 0x0CB4:
            case 0x0CC5:
            case 0x0CC9:
            case 0x0CDF:
            case 0x0D04:
            case 0x0D0D:
            case 0x0D11:
            case 0x0D29:
            case 0x0D49:
            case 0x0D84:
            case 0x0DB2:
            case 0x0DBC:
            case 0x0DD5:
            case 0x0DD7:
            case 0x0E83:
            case 0x0E89:
            case 0x0E98:
            case 0x0EA0:
            case 0x0EA4:
            case 0x0EA6:
            case 0x0EAC:
            case 0x0EBA:
            case 0x0EC5:
            case 0x0EC7:
            case 0x0F48:
            case 0x0F98:
            case 0x0FBD:
            case 0x1022:
            case 0x1028:
            case 0x102B:
            case 0x1207:
            case 0x1247:
            case 0x1249:
            case 0x1257:
            case 0x1259:
            case 0x1287:
            case 0x1289:
            case 0x12AF:
            case 0x12B1:
            case 0x12BF:
            case 0x12C1:
            case 0x12CF:
            case 0x12D7:
            case 0x12EF:
            case 0x130F:
            case 0x1311:
            case 0x131F:
            case 0x1347:
            case 0x170D:
            case 0x176D:
            case 0x1771:
            case 0x180F:
            case 0x1F58:
            case 0x1F5A:
            case 0x1F5C:
            case 0x1F5E:
            case 0x1FB5:
            case 0x1FC5:
            case 0x1FDC:
            case 0x1FF5:
            case 0x1FFF:
            case 0x24FF:
            case 0x2618:
            case 0x2705:
            case 0x2728:
            case 0x274C:
            case 0x274E:
            case 0x2757:
            case 0x27B0:
            case 0x2E9A:
            case 0x3040:
            case 0x318F:
            case 0x32FF:
            case 0x33FF:
            case 0xFB37:
            case 0xFB3D:
            case 0xFB3F:
            case 0xFB42:
            case 0xFB45:
            case 0xFE53:
            case 0xFE67:
            case 0xFE75:
            case 0xFF00:
            case 0xFFE7:
                throw new InvalidCharacterException( c );
            default:
                break;
        }

        // RFC 3454, Table A.1, intervals
        if ( ( c >= 0x0234 ) && ( c <= 0x024F ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x02AE ) && ( c <= 0x02AF ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x02EF ) && ( c <= 0x02FF ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0350 ) && ( c <= 0x035F ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0370 ) && ( c <= 0x0373 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0376 ) && ( c <= 0x0379 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x037B ) && ( c <= 0x037D ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x037F ) && ( c <= 0x0383 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x03F7 ) && ( c <= 0x03FF ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x04F6 ) && ( c <= 0x04F7 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x04FA ) && ( c <= 0x04FF ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0510 ) && ( c <= 0x0530 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0557 ) && ( c <= 0x0558 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x058B ) && ( c <= 0x0590 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x05C5 ) && ( c <= 0x05CF ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x05EB ) && ( c <= 0x05EF ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x05F5 ) && ( c <= 0x060B ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x060D ) && ( c <= 0x061A ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x061C ) && ( c <= 0x061E ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x063B ) && ( c <= 0x063F ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0656 ) && ( c <= 0x065F ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x06EE ) && ( c <= 0x06EF ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x072D ) && ( c <= 0x072F ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x074B ) && ( c <= 0x077F ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x07B2 ) && ( c <= 0x0900 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x093A ) && ( c <= 0x093B ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x094E ) && ( c <= 0x094F ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0955 ) && ( c <= 0x0957 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0971 ) && ( c <= 0x0980 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x098D ) && ( c <= 0x098E ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0991 ) && ( c <= 0x0992 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x09B3 ) && ( c <= 0x09B5 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x09BA ) && ( c <= 0x09BB ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x09C5 ) && ( c <= 0x09C6 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x09C9 ) && ( c <= 0x09CA ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x09CE ) && ( c <= 0x09D6 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x09D8 ) && ( c <= 0x09DB ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x09E4 ) && ( c <= 0x09E5 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x09FB ) && ( c <= 0x0A01 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0A03 ) && ( c <= 0x0A04 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0A0B ) && ( c <= 0x0A0E ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0A11 ) && ( c <= 0x0A12 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0A3A ) && ( c <= 0x0A3B ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0A43 ) && ( c <= 0x0A46 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0A49 ) && ( c <= 0x0A4A ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0A4E ) && ( c <= 0x0A58 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0A5F ) && ( c <= 0x0A65 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0A75 ) && ( c <= 0x0A80 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0ABA ) && ( c <= 0x0ABB ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0ACE ) && ( c <= 0x0ACF ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0AD1 ) && ( c <= 0x0ADF ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0AE1 ) && ( c <= 0x0AE5 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0AF0 ) && ( c <= 0x0B00 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0B0D ) && ( c <= 0x0B0E ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0B11 ) && ( c <= 0x0B12 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0B34 ) && ( c <= 0x0B35 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0B3A ) && ( c <= 0x0B3B ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0B44 ) && ( c <= 0x0B46 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0B49 ) && ( c <= 0x0B4A ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0B4E ) && ( c <= 0x0B55 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0B58 ) && ( c <= 0x0B5B ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0B62 ) && ( c <= 0x0B65 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0B71 ) && ( c <= 0x0B81 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0B8B ) && ( c <= 0x0B8D ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0B96 ) && ( c <= 0x0B98 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0BA0 ) && ( c <= 0x0BA2 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0BA5 ) && ( c <= 0x0BA7 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0BAB ) && ( c <= 0x0BAD ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0BBA ) && ( c <= 0x0BBD ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0BC3 ) && ( c <= 0x0BC5 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0BCE ) && ( c <= 0x0BD6 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0BD8 ) && ( c <= 0x0BE6 ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c >= 0x0BF3 ) && ( c <= 0x0C00 ) )
        {
            throw new InvalidCharacterException( c );
        }

        // RFC 3454, Table C.3
        if ( ( c >= 0xE000 ) && ( c <= 0xF8FF ) )
        {
            throw new InvalidCharacterException( c );
        }

        // RFC 3454, Table C.4
        if ( ( c >= 0xFDD0 ) && ( c <= 0xFDEF ) )
        {
            throw new InvalidCharacterException( c );
        }

        if ( ( c == 0xFFFE ) || ( c == 0xFFFF ) )
        {
            throw new InvalidCharacterException( c );
        }

        // RFC 3454, Table C.5 (Surrogates)
        if ( ( c >= 0xD800 ) && ( c <= 0xDFFF ) )
        {
            throw new InvalidCharacterException( c );
        }

        // RFC 3454, Table C.8 
        switch ( c )
        {
            case 0x0340: // COMBINING GRAVE TONE MARK
            case 0x0341: // COMBINING ACUTE TONE MARK
            case 0x200E: // LEFT-TO-RIGHT MARK
            case 0x200F: // RIGHT-TO-LEFT MARK
            case 0x202A: // LEFT-TO-RIGHT EMBEDDING
            case 0x202B: // RIGHT-TO-LEFT EMBEDDING
            case 0x202C: // POP DIRECTIONAL FORMATTING
            case 0x202D: // LEFT-TO-RIGHT OVERRIDE
            case 0x202E: // RIGHT-TO-LEFT OVERRIDE
            case 0x206A: // INHIBIT SYMMETRIC SWAPPING
            case 0x206B: // ACTIVATE SYMMETRIC SWAPPING
            case 0x206C: // INHIBIT ARABIC FORM SHAPING
            case 0x206D: // ACTIVATE ARABIC FORM SHAPING
            case 0x206E: // NATIONAL DIGIT SHAPES
            case 0x206F: // NOMINAL DIGIT SHAPES
                throw new InvalidCharacterException( c );
            default:
                break;
        }

        if ( c == 0xFFFD )
        {
            throw new InvalidCharacterException( c );
        }
    }


    /**
     * 
     * Remove all bidirectionnal chars. This is not really clear in RFC 4518
     * what we should do with bidi chars :
     * "Bidirectional characters are ignored."
     * 
     * But it's not explained what is a bidi chars...
     * 
     * So this method just do nothing atm.
     *
     * @param str The string where bidi chars are to be removed
     * @return The cleaned string
     */
    public static String bidi( String str )
    {
        return str;
    }


    /**
     * 
     * Remove all bidirectionnal chars. This is not really clear in RFC 4518
     * what we should do with bidi chars :
     * "Bidirectional characters are ignored."
     * 
     * But it's not explained what is a bidi chars...
     * 
     * So this method just do nothing atm.
     *
     * @param array The char array where bidi chars are to be removed
     * @return The cleaned StringBuilder
     */
    public static StringBuilder bidi( char[] array )
    {
        StringBuilder sb = new StringBuilder( array == null ? 0 : array.length );

        if ( array != null )
        {
            sb.append( array );
        }

        return sb;
    }


    /**
     * 
     * Remove all insignifiant chars in a Telephone Number :
     * Hyphen and spaces. 
     * 
     * For instance, the following telephone number :
     * "+ (33) 1-123--456  789"
     * will be trasnformed to :
     * "+(33)1123456789"
     *
     * @param str The telephone number
     * @return The modified telephone number String
     */
    private static String insignifiantCharTelephoneNumber( String str )
    {
        if ( Strings.isEmpty( str ) )
        {
            return "";
        }

        char[] array = str.toCharArray();

        boolean isSpaceOrHyphen = false;
        char soh = '\0';
        int pos = 0;

        for ( char c : array )
        {
            switch ( c )
            {
                case 0x0020: // SPACE
                case 0x002D: // HYPHEN-MINUS
                case 0x058A: // ARMENIAN HYPHEN
                case 0x2010: // HYPHEN
                case 0x2011: // NON-BREAKING HYPHEN
                case 0x2212: // MINUS SIGN
                case 0xFE63: // SMALL HYPHEN-MINUS
                case 0xFF0D: // FULLWIDTH HYPHEN-MINUS
                    soh = c;
                    isSpaceOrHyphen = true;
                    break;

                default:
                    if ( isSpaceOrHyphen && isCombiningMark( c ) )
                    {
                        array[pos++] = soh;
                        isSpaceOrHyphen = false;
                    }
                    else
                    {
                        isSpaceOrHyphen = false;
                    }

                    array[pos++] = c;
                    break;
            }
        }

        return new String( array, 0, pos );
    }


    /**
     * 
     * Remove all insignifiant spaces in a numeric string. For
     * instance, the following numeric string :
     * "  123  456  789  "
     * will be transformed to :
     * "123456789"
     *
     * @param str The numeric String
     * @return The modified numeric StringBuilder
     */
    private static String insignifiantCharNumericString( String str )
    {
        if ( Strings.isEmpty( str ) )
        {
            return "";
        }

        char[] array = str.toCharArray();

        boolean isSpace = false;
        int pos = 0;

        for ( char c : array )
        {
            if ( c != 0x20 )
            {
                if ( isSpace && isCombiningMark( c ) )
                {
                    array[pos++] = ' ';
                    isSpace = false;
                }

                array[pos++] = c;
            }
            else
            {
                isSpace = true;
            }
        }

        return new String( array, 0, pos );
    }


    /**
     * Remove all insignificant spaces in a string.
     * 
     * This method use a finite state machine to parse
     * the text.
     * 
     * @param str The String to modify
     * @param caseSensitive A flag telling if the chars must be lower cased
     * @return The modified StringBuilder
     * @throws InvalidCharacterException If an invalid character is found in the String
     */
    private static String insignifiantSpacesString( String str, boolean caseSensitive )
        throws InvalidCharacterException
    {
        if ( Strings.isEmpty( str ) )
        {
            // Special case : an empty strings is replaced by 2 spaces
            return "";
        }

        char[] array = str.toCharArray();

        // Create a target char array which is 3 times bigger than the original size. 
        // We have to do that because the map phase may transform a char to
        // three chars.
        // TODO : we have to find a way to prevent this waste of space.
        char[] target = new char[str.length() * 3 + 2];
        
        int pos;
        char lowerCase = ( char ) ( caseSensitive ? 0x00 : 0x20 );

        // First pass to map the chars. This will copy the array into the target
        int limit = map( array, target, lowerCase );
        pos = 0;

        // Second pass to remove spaces. We work on the target
        int start = 0;
        char c = '\0';

        // First remove starting spaces
        for ( int i = 0; i < limit; i++ )
        {
            c = target[i];

            if ( c != ' ' )
            {
                checkProhibited( c );
                break;
            }
            
            start++;
        }

        // We will just handle the special case of a combining character
        if ( start == limit )
        {
            // we only have spaces, we keep only one
            return " ";
        }
        else if ( isCombiningMark( c ) )
        {
            if ( start == 0 )
            {
                // The first char can't be a combining char
                throw new InvalidCharacterException( c );
            }
            else
            {
                target[pos++] = ' ';
                target[pos++] = c;
                start++;
            }
        }
        else
        {
            target[pos++] = c;
            start++;
        }

        // Now remove the spaces at the end
        int i;
        
        for ( i = limit - 1; i >= start; i-- )
        {
            if ( target[i] == ' ' )
            {
                // Check if we have a preceding '\' 
                if ( i - 1 >= start )
                {
                    // Break only if the space is preceded by a single ESC
                    if ( i - 2 >= start )
                    {
                        if ( ( target[i - 1] == '\\' ) && ( target[i - 2] != '\\' ) )
                        {
                            target[i - 1] = ' ';
                            i--;
                            break;
                        }
                    }
                    else
                    {
                        if ( target[i - 1] == '\\' )
                        {
                            target[i - 1] = ' ';
                            i--;
                            break;
                        }
                    }
                }
            }
            else
            {
                break;
            }
        }

        limit = i + 1;

        // Remove the " around the string if any
        if ( target[start] == '"' )
        {
            start++;
            limit--;
        }

        boolean spaceSeen = false;
        boolean escapeSeen = false;

        for ( i = start; i < limit; i++ )
        {
            c = target[i];

            checkProhibited( c );

            if ( c == ' ' )
            {
                if ( escapeSeen )
                {
                    target[pos++] = ' ';
                }
                else
                {
                    spaceSeen = true;
                }

                escapeSeen = false;
            }
            else if ( c == '\\' )
            {
                if ( escapeSeen )
                {
                    target[pos++] = '\\';
                    target[pos++] = '\\';
                }
                else if ( spaceSeen )
                {
                    target[pos++] = ' ';
                }
                
                escapeSeen = !escapeSeen;
                spaceSeen = false;
            }
            else
            {
                if ( spaceSeen )
                {
                    target[pos++] = ' ';
                    spaceSeen = false;
                }
                else if ( escapeSeen )
                {
                    target[pos++] = '\\';
                }
                
                target[pos++] = c;
                escapeSeen = false;
            }
        }

        // A special case : we have seen a space at the end of the array : it must be added back
        // because it's an escaped space, otherwise it would have been discarded by the previous 
        // end of String's space removal
        if ( spaceSeen )
        {
            target[pos++] = ' ';
        }
        // Same for the escape
        else if ( escapeSeen )
        {
            target[pos++] = '\\';
        }
        
        // Ends by unescaping the escaped elements
        return unescape( target, pos );
    }


    /**
     * Remove all insignificant spaces in a Ascii string. We don't remove escaped spaces.
     * 
     * This method use a finite state machine to parse
     * the text.
     * 
     * @param str The String to modify
     * @param caseSensitive A flag telling if the chars must be lower cased
     * @return The modified StringBuilder
     * @throws InvalidCharacterException If an invalid character is found in the String
     */
    private static String insignifiantSpacesStringAscii( String str, boolean caseSensitive )
        throws InvalidCharacterException
    {
        if ( Strings.isEmpty( str ) )
        {
            // Special case : an empty strings is replaced by 2 spaces
            return "";
        }
        
        char[] array = str.toCharArray();

        int pos;
        char lowerCase = ( char ) ( caseSensitive ? 0x00 : 0x20 );

        // First pass to map the chars
        int limit = map( array, array, lowerCase );
        pos = 0;

        // Second pass to remove spaces (except the escaped ones). We work on the target
        int start = 0;
        char c = '\0';

        // First remove starting spaces
        for ( int i = 0; i < limit; i++ )
        {
            c = array[i];

            if ( c != ' ' )
            {
                checkProhibited( c );
                break;
            }
            
            start++;
        }

        // We will just handle the special case of a combining character
        if ( start == limit )
        {
            // we only have spaces, we keep only one
            return " ";
        }
        else if ( isCombiningMark( c ) )
        {
            if ( start == 0 )
            {
                // The first char can't be a combining char
                throw new InvalidCharacterException( c );
            }
            else
            {
                throw new InvalidCharacterException( c );
            }
        }

        // Now remove the spaces at the end
        int i;
        
        for ( i = limit - 1; i >= start; i-- )
        {
            if ( array[i] == ' ' )
            {
                // Check if we have a preceding '\' 
                if ( i - 1 >= start )
                {
                    // Break only if the space is preceded by a single ESC
                    if ( i - 2 >= start )
                    {
                        if ( ( array[i - 1] == '\\' ) && ( array[i - 2] != '\\' ) )
                        {
                            array[i - 1] = ' ';
                            i--;
                            break;
                        }
                    }
                    else
                    {
                        if ( array[i - 1] == '\\' )
                        {
                            array[i - 1] = ' ';
                            i--;
                            break;
                        }
                    }
                }
            }
            else
            {
                break;
            }
        }

        limit = i + 1;

        // Remove the " around the string if any
        if ( array[start] == '"' )
        {
            start++;
            limit--;
        }
        
        boolean spaceSeen = false;
        boolean escapeSeen = false;

        for ( i = start; i < limit; i++ )
        {
            c = array[i];

            checkProhibited( c );

            if ( c == ' ' )
            {
                if ( escapeSeen )
                {
                    array[pos++] = ' ';
                }
                else
                {
                    spaceSeen = true;
                }

                escapeSeen = false;
            }
            else if ( c == '\\' )
            {
                if ( escapeSeen )
                {
                    array[pos++] = '\\';
                    array[pos++] = '\\';
                }
                else if ( spaceSeen )
                {
                    array[pos++] = ' ';
                }
                
                escapeSeen = !escapeSeen;
                spaceSeen = false;
            }
            else
            {
                if ( spaceSeen )
                {
                    array[pos++] = ' ';
                    spaceSeen = false;
                }
                else if ( escapeSeen )
                {
                    array[pos++] = '\\';
                }
                
                array[pos++] = c;
                escapeSeen = false;
            }
        }

        // A special case : we have seen a space at the end of the array : it must be added back
        // because it's an escaped space, otherwise it would have been discarded by the previous 
        // end of String's space removal
        if ( spaceSeen )
        {
            array[pos++] = ' ';
        }
        // Same for the escape
        else if ( escapeSeen )
        {
            array[pos++] = '\\';
        }
        
        // Ends by unescaping the escaped elements
        return unescape( array, pos );
    }
    
    
    private static String unescape( char[] array, int end )
    {
        byte[] bytes = new byte[end * 3];
        boolean escapeSeen = false;
        int pos = 0;
            
        for ( int i = 0; i < end; i++ )
        {
            char c = array[i];
            
            if ( c == '\\' )
            {
                if ( escapeSeen )
                {
                    bytes[pos++] = '\\';
                }
                
                escapeSeen = !escapeSeen;
            }
            else
            {
                if ( escapeSeen )
                {
                    switch ( c )
                    {
                        // Various form of space
                        case 0x0A :
                        case 0x0B :
                        case 0x0C :
                        case 0x0D :
                        case 0x85 :
                        case 0xA0 :
                        case ' ' :
                            bytes[pos++] = ' ';
                            break;
                        
                        // Special chars
                        case '#' :
                        case '=' :
                        case '+' :
                        case '"' :
                        case ',' :
                        case ';' :
                        case '<' :
                        case '>' : 
                            bytes[pos++] = ( byte ) c;
                            break;
                        
                        // Hexpair
                        case '0' :
                        case '1' :
                        case '2' :
                        case '3' :
                        case '4' :
                        case '5' :
                        case '6' :
                        case '7' :
                        case '8' :
                        case '9' :
                            bytes[pos++] = ( byte ) ( ( ( byte ) ( array[i] - '0' ) << 4 ) 
                                + ( toByte( array[i + 1] ) & 0xff ) );
                            i++;
                            break;
                            
                        case 'a' :
                        case 'b' :
                        case 'c' :
                        case 'd' :
                        case 'e' :
                        case 'f' :
                            bytes[pos++] = ( byte ) ( ( ( byte ) ( array[i] - 'a' + 10 ) << 4 ) 
                                + ( toByte( array[i + 1] ) & 0xFF ) );
                            i++;
                            break;
                            
                        case 'A' :
                        case 'B' :
                        case 'C' :
                        case 'D' :
                        case 'E' :
                        case 'F' :
                            bytes[pos++] = ( byte ) ( ( ( byte ) ( array[i] - 'A' + 10 ) << 4 ) 
                                + ( toByte( array[i + 1] ) & 0xff ) );
                            i++;
                            break;
                            
                        default :
                            break;
                    }
                    
                    escapeSeen = false;
                }
                else
                {
                    // We might have a UTF-8 char
                    if ( ( c & 0x007F ) == c )
                    {
                        // Single byte char
                        bytes[pos++] = ( byte ) c;
                    }
                    else if ( ( c & 0x07FF ) == c )
                    {
                        bytes[pos++] = ( byte ) ( 0x00C0 | ( c >> 6 ) );
                        bytes[pos++] = ( byte ) ( 0x0080 | ( c & 0x003F ) );
                    }
                    else
                    {
                        bytes[pos++] = ( byte ) ( 0x00E0 | ( c >> 12 ) );
                        bytes[pos++] = ( byte ) ( 0x0080 | ( ( c >> 6 ) & 0x3F ) );
                        bytes[pos++] = ( byte ) ( 0x0080 | ( c & 0x003F ) );
                    }
                }
            }
        }
        
        // Deal with the special case where we have one single escape
        if ( escapeSeen )
        {
            bytes[pos++] = '\\';
        }
        
        return Strings.utf8ToString( bytes, pos );
    }
    
    
    private static byte toByte( char c )
    {
        switch ( c )
        {
            case '0' :
            case '1' :
            case '2' :
            case '3' :
            case '4' :
            case '5' :
            case '6' :
            case '7' :
            case '8' :
            case '9' :
                return ( byte ) ( c - '0' );
                
            case 'a' :
            case 'b' :
            case 'c' :
            case 'd' :
            case 'e' :
            case 'f' :
                return ( byte ) ( c - 'a' + 10 );
                
            case 'A' :
            case 'B' :
            case 'C' :
            case 'D' :
            case 'E' :
            case 'F' :
                return ( byte ) ( c - 'A' + 10 );
                
            default :
                break;
        }
        
        return 0;
    }
}
