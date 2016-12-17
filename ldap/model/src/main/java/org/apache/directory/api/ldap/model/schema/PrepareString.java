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


import java.text.Normalizer;

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
    private enum NormStateEnum
    {
        START,
        INITIAL_CHAR,
        INITIAL_SPACES,
        SPACES,
        CHARS,
        SPACE_CHAR,
        END
    }
    
    /** A flag used to lowercase chars during the map process */
    public static final boolean CASE_SENSITIVE = true;

    /** A flag used to keep casing during the map process */
    public static final boolean IGNORE_CASE = false;

    /**
     * The type of Assertion we have to normalize
     */
    public enum AssertionType
    {
        /** The INITIAL part of a substring assertion value */
        SUBSTRING_INITIAL,
        
        /** The ANY part of a substring assertion value */
        SUBSTRING_ANY,
        
        /** The FINAL part of a substring assertion value */
        SUBSTRING_FINAL,
        
        /** An Attribute Value */
        ATTRIBUTE_VALUE
    }
    
    /** An exception used to get out of the map method quickly */
    private static final ArrayIndexOutOfBoundsException AIOOBE = new ArrayIndexOutOfBoundsException();
    
    /**
     * A private constructor, to avoid instance creation of this static class.
     */
    private PrepareString()
    {
        // Do nothing
    }


    /**
     * The first step defined by RFC 4518 : Transcode, which transform an
     * UTF-8 encoded String to Unicode. This is done using the {@link Strings#utf8ToString} 
     * method. This 
     * 
     * @param bytes The byte[] to transcode
     * @return The transcoded String
     */
    public static String transcode( byte[] bytes )
    {
        return Strings.utf8ToString( bytes );
    }
    
    
    /**
     * Normalize a String 
     * 
     * @param value the value to normalize
     * @return The normalized value
     */
    public static String normalize( String value )
    {
        if ( !Normalizer.isNormalized( value, Normalizer.Form.NFKC ) )
        {
            return Normalizer.normalize( value, Normalizer.Form.NFKC );
        }
        else
        {
            return value;
        }
    }
    
    
    /**
     * Apply the RFC 4518 MAP transformation, case sensitive
     * 
     * @param unicode The original String
     * @return The mapped String
     */
    public static String mapCaseSensitive( String unicode )
    {
        try
        {
            return mapCaseSensitiveAscii( unicode );
        }
        catch ( ArrayIndexOutOfBoundsException aioobe )
        {
            // There 
        }

        char[] source = unicode.toCharArray();

        // Create a target char array which is 3 times bigger than the original size. 
        // We have to do that because the map phase may transform a char to
        // three chars.
        // TODO : we have to find a way to prevent this waste of space.
        char[] target = new char[unicode.length() * 3 + 2];

        int limit = 0;

        for ( char c : source )
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
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: U+0000-0008...
                    break;

                case 0x0009:
                case 0x000A:
                case 0x000B:
                case 0x000C:
                case 0x000D:
                    // CHARACTER TABULATION (U+0009), LINE FEED (LF) (U+000A), LINE
                    // TABULATION (U+000B), FORM FEED (FF) (U+000C), CARRIAGE RETURN (CR)
                    // (U+000D), ... are mapped to SPACE (U+0020).
                    target[limit++] = 0x0020;
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
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+000E-001F...
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
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0041-005A
                    target[limit++] = c;
                    break;

                case 0x007F:
                case 0x0080:
                case 0x0081:
                case 0x0082:
                case 0x0083:
                case 0x0084:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+007F-0084...
                    break;

                case 0x0085:
                    // ... and NEXT LINE (NEL) (U+0085) are mapped to SPACE (U+0020).
                    target[limit++] = 0x0020;
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
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+0086-009F...
                    break;

                case 0x00A0:
                    // All other code points with Separator (space, line, or paragraph) property 
                    // (e.g., Zs, Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
                    //  list of these code points: ... 00A0 ...
                    target[limit++] = 0x0020;
                    break;

                case 0x00AD:
                    // SOFT HYPHEN (U+00AD) and MONGOLIAN TODO SOFT HYPHEN (U+1806) code
                    // points are mapped to nothing.  COMBINING GRAPHEME JOINER (U+034F) and
                    // VARIATION SELECTORs (U+180B-180D, FF00-FE0F) code points are also
                    // mapped to nothing.  The OBJECT REPLACEMENT CHARACTER (U+FFFC) is
                    // mapped to nothing.
                    break;

                case 0x00B5:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+00B5
                    target[limit++] = 0x03BC;
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
                // no 0x00D7
                case 0x00D6:
                case 0x00D8:
                case 0x00D9:
                case 0x00DA:
                case 0x00DB:
                case 0x00DC:
                case 0x00DD:
                case 0x00DE:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+00C0-00D6,
                    // U+00D8-00DE
                    target[limit++] = c;
                    break;

                case 0x00DF:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+00DF
                    target[limit++] = 0x0073;
                    target[limit++] = 0x0073;
                    break;

                case 0x0100:
                case 0x0102:
                case 0x0104:
                case 0x0106:
                case 0x0108:
                case 0x010A:
                case 0x010C:
                case 0x010E:
                case 0x0110:
                case 0x0112:
                case 0x0114:
                case 0x0116:
                case 0x0118:
                case 0x011A:
                case 0x011C:
                case 0x011E:
                case 0x0120:
                case 0x0122:
                case 0x0124:
                case 0x0126:
                case 0x0128:
                case 0x012A:
                case 0x012C:
                case 0x012E:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0100-012E
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;

                case 0x0130:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0130
                    target[limit++] = 0x0069;
                    target[limit++] = 0x0307;
                    break;

                case 0x0132:
                case 0x0134:
                case 0x0136:
                case 0x0139:
                case 0x013B:
                case 0x013D:
                case 0x013F:
                case 0x0141:
                case 0x0143:
                case 0x0145:
                case 0x0147:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0132-0147
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;

                case 0x0149:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0149
                    target[limit++] = 0x02BC;
                    target[limit++] = 0x006E;
                    break;

                case 0x014A:
                case 0x014C:
                case 0x014E:
                case 0x0150:
                case 0x0152:
                case 0x0154:
                case 0x0156:
                case 0x0158:
                case 0x015A:
                case 0x015C:
                case 0x015E:
                case 0x0160:
                case 0x0162:
                case 0x0164:
                case 0x0166:
                case 0x0168:
                case 0x016A:
                case 0x016C:
                case 0x016E:
                case 0x0170:
                case 0x0172:
                case 0x0174:
                case 0x0176:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0141-0176
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;

                case 0x0178:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0178
                    target[limit++] = 0x00FF;
                    break;

                case 0x0179:
                case 0x017B:
                case 0x017D:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0179-017D
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;

                case 0x017F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+017F
                    target[limit++] = 0x0073;
                    break;

                case 0x0181:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0181
                    target[limit++] = 0x0253;
                    break;

                case 0x0182:
                case 0x0184:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0182, U+0x0184
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;

                case 0x0186:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0186
                    target[limit++] = 0x0254;
                    break;

                case 0x0187:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0188
                    target[limit++] = 0x0188;
                    break;

                case 0x0189:
                case 0x018A:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0189, U+018A
                    target[limit++] = ( char ) ( c + 0x00CD );
                    break;

                case 0x018B:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+018B
                    target[limit++] = 0x018C;
                    break;

                case 0x018E:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+018E
                    target[limit++] = 0x01DD;
                    break;

                case 0x018F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+018F
                    target[limit++] = 0x0259;
                    break;

                case 0x0190:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0190
                    target[limit++] = 0x025B;
                    break;

                case 0x0191:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0191
                    target[limit++] = 0x0192;
                    break;

                case 0x0193:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0193
                    target[limit++] = 0x0260;
                    break;

                case 0x0194:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0194
                    target[limit++] = 0x0263;
                    break;

                case 0x0196:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0196
                    target[limit++] = 0x0269;
                    break;

                case 0x0197:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0197
                    target[limit++] = 0x0268;
                    break;

                case 0x0198:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0198
                    target[limit++] = 0x0199;
                    break;

                case 0x019C:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+019C
                    target[limit++] = 0x026F;
                    break;

                case 0x019D:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+019D
                    target[limit++] = 0x0272;
                    break;

                case 0x019F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+019F
                    target[limit++] = 0x0275;
                    break;

                case 0x01A0:
                case 0x01A2:
                case 0x01A4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01A0-U+01A4
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;

                case 0x01A6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01A6
                    target[limit++] = 0x0280;
                    break;

                case 0x01A7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01A7
                    target[limit++] = 0x01A8;
                    break;

                case 0x01A9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01A9
                    target[limit++] = 0x0283;
                    break;

                case 0x01AC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01AC
                    target[limit++] = 0x01AD;
                    break;

                case 0x01AE:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01AE
                    target[limit++] = 0x0288;
                    break;

                case 0x01AF:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01AF
                    target[limit++] = 0x01B0;
                    break;

                case 0x01B1:
                case 0x01B2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01AF, U+01B2
                    target[limit++] = ( char ) ( c + 0x00D9 );
                    break;

                case 0x01B3:
                case 0x01B5:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01B3, U+01B5
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;

                case 0x01B7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01B7
                    target[limit++] = 0x0292;
                    break;

                case 0x01B8:
                case 0x01BC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01B8, U+01BC
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;

                case 0x01C4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01C4,U+01C5
                    target[limit++] = 0x01C6;
                    break;

                case 0x01C7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01C7,U+01C8
                    target[limit++] = 0x01C9;
                    break;

                case 0x01CA:
                case 0x01CB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01CA,U+01CB
                    target[limit++] = 0x01CC;
                    break;

                case 0x01CD:
                case 0x01CF:
                case 0x01D1:
                case 0x01D3:
                case 0x01D5:
                case 0x01D7:
                case 0x01D9:
                case 0x01DB:
                case 0x01DE:
                case 0x01E0:
                case 0x01E2:
                case 0x01E4:
                case 0x01E6:
                case 0x01E8:
                case 0x01EA:
                case 0x01EC:
                case 0x01EE:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01CD, U+01EE
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;

                case 0x01F0:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01F0
                    target[limit++] = 0x006A;
                    target[limit++] = 0x030C;
                    break;

                case 0x01F1:
                case 0x01F2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01F1, U+01F2
                    target[limit++] = 0x01F3;
                    break;

                case 0x01F4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01F4
                    target[limit++] = 0x01F5;
                    break;

                case 0x01F6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01F6
                    target[limit++] = 0x0195;
                    break;

                case 0x01F7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01F7
                    target[limit++] = 0x01BF;
                    break;

                case 0x01F8:
                case 0x01FA:
                case 0x01FC:
                case 0x01FE:
                case 0x0200:
                case 0x0202:
                case 0x0204:
                case 0x0206:
                case 0x0208:
                case 0x020A:
                case 0x020C:
                case 0x020E:
                case 0x0210:
                case 0x0212:
                case 0x0214:
                case 0x0216:
                case 0x0218:
                case 0x021A:
                case 0x021C:
                case 0x021E:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01F8-U+021E
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;


                case 0x0220:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0220
                    target[limit++] = 0x019E;
                    break;

                case 0x0222:
                case 0x0224:
                case 0x0226:
                case 0x0228:
                case 0x022A:
                case 0x022C:
                case 0x022E:
                case 0x0230:
                case 0x0232:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0222-U+0232
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;

                case 0x0345:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0220
                    target[limit++] = 0x03B9;
                    break;

                case 0x034F:
                    // SOFT HYPHEN (U+00AD) and MONGOLIAN TODO SOFT HYPHEN (U+1806) code
                    // points are mapped to nothing.  COMBINING GRAPHEME JOINER (U+034F) and
                    // VARIATION SELECTORs (U+180B-180D, FF00-FE0F) code points are also
                    // mapped to nothing.  The OBJECT REPLACEMENT CHARACTER (U+FFFC) is
                    // mapped to nothing.
                    break;

                case 0x037A:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+037A
                    target[limit++] = 0x0020;
                    target[limit++] = 0x03B9;
                    break;

                case 0x0386:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0386
                    target[limit++] = 0x03AC;
                    break;

                case 0x0388:
                case 0x0389:
                case 0x038A:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0388, U+0389, U+038A
                    target[limit++] = ( char ) ( c + 0x0025 );
                    break;

                case 0x038C:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+038C
                    target[limit++] = 0x03CC;
                    break;

                case 0x038E:
                case 0x038F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+038E, U+038F
                    target[limit++] = ( char ) ( c + 0x0025 );
                    break;

                case 0x0390:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0390
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0301;
                    break;

                case 0x0391:
                case 0x0392:
                case 0x0393:
                case 0x0394:
                case 0x0395:
                case 0x0396:
                case 0x0397:
                case 0x0398:
                case 0x0399:
                case 0x039A:
                case 0x039B:
                case 0x039C:
                case 0x039D:
                case 0x039E:
                case 0x039F:
                case 0x03A0:
                case 0x03A1:
                case 0x03A3:
                case 0x03A4:
                case 0x03A5:
                case 0x03A6:
                case 0x03A7:
                case 0x03A8:
                case 0x03A9:
                case 0x03AA:
                case 0x03AB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0391-U+03AB
                    target[limit++] = ( char ) ( c + 0x0020 );
                    break;


                case 0x03B0:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03B0
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0301;
                    break;

                case 0x03C2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03C2
                    target[limit++] = 0x03C3;
                    break;

                case 0x03D0:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D0
                    target[limit++] = 0x03B2;
                    break;

                case 0x03D1:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D1
                    target[limit++] = 0x03B8;
                    break;

                case 0x03D2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D2
                    target[limit++] = 0x03C5;
                    break;

                case 0x03D3:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D3
                    target[limit++] = 0x03CD;
                    break;

                case 0x03D4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D4
                    target[limit++] = 0x03CB;
                    break;

                case 0x03D5:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D5
                    target[limit++] = 0x03C6;
                    break;

                case 0x03D6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D6
                    target[limit++] = 0x03C0;
                    break;

                case 0x03D8:
                case 0x03DA:
                case 0x03DC:
                case 0x03DE:
                case 0x03E0:
                case 0x03E2:
                case 0x03E4:
                case 0x03E6:
                case 0x03E8:
                case 0x03EA:
                case 0x03EC:
                case 0x03EE:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D8-U+03EE
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;

                case 0x03F0:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03F0
                    target[limit++] = 0x03BA;
                    break;

                case 0x03F1:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03F1
                    target[limit++] = 0x03C1;
                    break;

                case 0x03F2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03F2
                    target[limit++] = 0x03C3;
                    break;

                case 0x03F4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03F4
                    target[limit++] = 0x03B8;
                    break;

                case 0x03F5:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03F5
                    target[limit++] = 0x03B5;
                    break;

                case 0x0400:
                case 0x0401:
                case 0x0402:
                case 0x0403:
                case 0x0404:
                case 0x0405:
                case 0x0406:
                case 0x0407:
                case 0x0408:
                case 0x0409:
                case 0x040A:
                case 0x040B:
                case 0x040C:
                case 0x040D:
                case 0x040E:
                case 0x040F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0400-U+040F
                    target[limit++] = ( char ) ( c + 0x0050 );
                    break;

                case 0x0410:
                case 0x0411:
                case 0x0412:
                case 0x0413:
                case 0x0414:
                case 0x0415:
                case 0x0416:
                case 0x0417:
                case 0x0418:
                case 0x0419:
                case 0x041A:
                case 0x041B:
                case 0x041C:
                case 0x041D:
                case 0x041E:
                case 0x041F:
                case 0x0420:
                case 0x0421:
                case 0x0422:
                case 0x0423:
                case 0x0424:
                case 0x0425:
                case 0x0426:
                case 0x0427:
                case 0x0428:
                case 0x0429:
                case 0x042A:
                case 0x042B:
                case 0x042C:
                case 0x042D:
                case 0x042E:
                case 0x042F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0410-U+042F
                    target[limit++] = ( char ) ( c + 0x0020 );
                    break;

                case 0x0460:
                case 0x0462:
                case 0x0464:
                case 0x0466:
                case 0x0468:
                case 0x046A:
                case 0x046C:
                case 0x046E:
                case 0x0470:
                case 0x0472:
                case 0x0474:
                case 0x0476:
                case 0x0478:
                case 0x047A:
                case 0x047C:
                case 0x047E:
                case 0x0480:
                case 0x048A:
                case 0x048C:
                case 0x048E:
                case 0x0490:
                case 0x0492:
                case 0x0494:
                case 0x0496:
                case 0x0498:
                case 0x049A:
                case 0x049C:
                case 0x049E:
                case 0x04A0:
                case 0x04A2:
                case 0x04A4:
                case 0x04A6:
                case 0x04A8:
                case 0x04AA:
                case 0x04AC:
                case 0x04AE:
                case 0x04B0:
                case 0x04B2:
                case 0x04B4:
                case 0x04B6:
                case 0x04B8:
                case 0x04BA:
                case 0x04BC:
                case 0x04BE:
                case 0x04C1:
                case 0x04C3:
                case 0x04C5:
                case 0x04C7:
                case 0x04C9:
                case 0x04CB:
                case 0x04CD:
                case 0x04D0:
                case 0x04D2:
                case 0x04D4:
                case 0x04D6:
                case 0x04D8:
                case 0x04DA:
                case 0x04DC:
                case 0x04DE:
                case 0x04E0:
                case 0x04E2:
                case 0x04E4:
                case 0x04E6:
                case 0x04E8:
                case 0x04EA:
                case 0x04EC:
                case 0x04EE:
                case 0x04F0:
                case 0x04F2:
                case 0x04F4:
                case 0x04F8:
                case 0x0500:
                case 0x0502:
                case 0x0504:
                case 0x0506:
                case 0x0508:
                case 0x050A:
                case 0x050C:
                case 0x050E:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0460-U+050E
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;

                case 0x0531:
                case 0x0532:
                case 0x0533:
                case 0x0534:
                case 0x0535:
                case 0x0536:
                case 0x0537:
                case 0x0538:
                case 0x0539:
                case 0x053A:
                case 0x053B:
                case 0x053C:
                case 0x053D:
                case 0x053E:
                case 0x053F:
                case 0x0540:
                case 0x0541:
                case 0x0542:
                case 0x0543:
                case 0x0544:
                case 0x0545:
                case 0x0546:
                case 0x0547:
                case 0x0548:
                case 0x0549:
                case 0x054A:
                case 0x054B:
                case 0x054C:
                case 0x054D:
                case 0x054E:
                case 0x054F:
                case 0x0550:
                case 0x0551:
                case 0x0552:
                case 0x0553:
                case 0x0554:
                case 0x0555:
                case 0x0556:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0531-U+0556
                    target[limit++] = ( char ) ( c + 0x0030 );
                    break;


                case 0x0587:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0587
                    target[limit++] = 0x0565;
                    target[limit++] = 0x0582;
                    break;

                case 0x06DD:
                case 0x070F:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+06DD-070F...
                    break;

                case 0x1680:
                    // All other code points with Separator (space, line, or paragraph) property 
                    // (e.g., Zs, Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
                    //  list of these code points: ...1680...
                    target[limit++] = 0x0020;
                    break;

                case 0x1806:
                    // SOFT HYPHEN (U+00AD) and MONGOLIAN TODO SOFT HYPHEN (U+1806) code
                    // points are mapped to nothing.  COMBINING GRAPHEME JOINER (U+034F) and
                    // VARIATION SELECTORs (U+180B-180D, FF00-FE0F) code points are also
                    // mapped to nothing.  The OBJECT REPLACEMENT CHARACTER (U+FFFC) is
                    // mapped to nothing.
                    break;

                case 0x180B:
                case 0x180C:
                case 0x180D:
                    // SOFT HYPHEN (U+00AD) and MONGOLIAN TODO SOFT HYPHEN (U+1806) code
                    // points are mapped to nothing.  COMBINING GRAPHEME JOINER (U+034F) and
                    // VARIATION SELECTORs (U+180B-180D, FF00-FE0F) code points are also
                    // mapped to nothing.  The OBJECT REPLACEMENT CHARACTER (U+FFFC) is
                    // mapped to nothing.
                    break;
                    
                case 0x180E:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+180E...
                    break;

                case 0x1E00:
                case 0x1E02:
                case 0x1E04:
                case 0x1E06:
                case 0x1E08:
                case 0x1E0A:
                case 0x1E0C:
                case 0x1E0E:
                case 0x1E10:
                case 0x1E12:
                case 0x1E14:
                case 0x1E16:
                case 0x1E18:
                case 0x1E1A:
                case 0x1E1C:
                case 0x1E1E:
                case 0x1E20:
                case 0x1E22:
                case 0x1E24:
                case 0x1E26:
                case 0x1E28:
                case 0x1E2A:
                case 0x1E2C:
                case 0x1E2E:
                case 0x1E30:
                case 0x1E32:
                case 0x1E34:
                case 0x1E36:
                case 0x1E38:
                case 0x1E3A:
                case 0x1E3C:
                case 0x1E3E:
                case 0x1E40:
                case 0x1E42:
                case 0x1E44:
                case 0x1E46:
                case 0x1E48:
                case 0x1E4A:
                case 0x1E4C:
                case 0x1E4E:
                case 0x1E50:
                case 0x1E52:
                case 0x1E54:
                case 0x1E56:
                case 0x1E58:
                case 0x1E5A:
                case 0x1E5C:
                case 0x1E5E:
                case 0x1E60:
                case 0x1E62:
                case 0x1E64:
                case 0x1E66:
                case 0x1E68:
                case 0x1E6A:
                case 0x1E6C:
                case 0x1E6E:
                case 0x1E70:
                case 0x1E72:
                case 0x1E74:
                case 0x1E76:
                case 0x1E78:
                case 0x1E7A:
                case 0x1E7C:
                case 0x1E7E:
                case 0x1E80:
                case 0x1E82:
                case 0x1E84:
                case 0x1E86:
                case 0x1E88:
                case 0x1E8A:
                case 0x1E8C:
                case 0x1E8E:
                case 0x1E90:
                case 0x1E92:
                case 0x1E94:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1E00-U+1E94
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;

                case 0x1E96:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1E96
                    target[limit++] = 0x0068;
                    target[limit++] = 0x0331;
                    break;

                case 0x1E97:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1E97
                    target[limit++] = 0x0074;
                    target[limit++] = 0x0308;
                    break;

                case 0x1E98:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1E98
                    target[limit++] = 0x0077;
                    target[limit++] = 0x030A;
                    break;

                case 0x1E99:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1E99
                    target[limit++] = 0x0079;
                    target[limit++] = 0x030A;
                    break;

                case 0x1E9A:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1E9A
                    target[limit++] = 0x0061;
                    target[limit++] = 0x02BE;
                    break;

                case 0x1E9B:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1E9B
                    target[limit++] = 0x1E61;
                    break;

                case 0x1EA0:
                case 0x1EA2:
                case 0x1EA4:
                case 0x1EA6:
                case 0x1EA8:
                case 0x1EAA:
                case 0x1EAC:
                case 0x1EAE:
                case 0x1EB0:
                case 0x1EB2:
                case 0x1EB4:
                case 0x1EB6:
                case 0x1EB8:
                case 0x1EBA:
                case 0x1EBC:
                case 0x1EBE:
                case 0x1EC0:
                case 0x1EC2:
                case 0x1EC4:
                case 0x1EC6:
                case 0x1EC8:
                case 0x1ECA:
                case 0x1ECC:
                case 0x1ECE:
                case 0x1ED0:
                case 0x1ED2:
                case 0x1ED4:
                case 0x1ED6:
                case 0x1ED8:
                case 0x1EDA:
                case 0x1EDC:
                case 0x1EDE:
                case 0x1EE0:
                case 0x1EE2:
                case 0x1EE4:
                case 0x1EE6:
                case 0x1EE8:
                case 0x1EEA:
                case 0x1EEC:
                case 0x1EEE:
                case 0x1EF0:
                case 0x1EF2:
                case 0x1EF4:
                case 0x1EF6:
                case 0x1EF8:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1EA0-U+1EF8
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;

                case 0x1F08:
                case 0x1F09:
                case 0x1F0A:
                case 0x1F0B:
                case 0x1F0C:
                case 0x1F0D:
                case 0x1F0E:
                case 0x1F0F:
                case 0x1F18:
                case 0x1F19:
                case 0x1F1A:
                case 0x1F1B:
                case 0x1F1C:
                case 0x1F1D:
                case 0x1F28:
                case 0x1F29:
                case 0x1F2A:
                case 0x1F2B:
                case 0x1F2C:
                case 0x1F2D:
                case 0x1F2E:
                case 0x1F2F:
                case 0x1F38:
                case 0x1F39:
                case 0x1F3A:
                case 0x1F3B:
                case 0x1F3C:
                case 0x1F3D:
                case 0x1F3E:
                case 0x1F3F:
                case 0x1F48:
                case 0x1F49:
                case 0x1F4A:
                case 0x1F4B:
                case 0x1F4C:
                case 0x1F4D:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F08-U+1F4D
                    target[limit++] = ( char ) ( c - 0x0008 );
                    break;

                case 0x1F50:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F50
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0313;
                    break;

                case 0x1F52:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F52
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0313;
                    target[limit++] = 0x0300;
                    break;

                case 0x1F54:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F54
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0313;
                    target[limit++] = 0x0301;
                    break;

                case 0x1F56:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F56
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0313;
                    target[limit++] = 0x0342;
                    break;

                case 0x1F59:
                case 0x1F5B:
                case 0x1F5D:
                case 0x1F5F:
                case 0x1F68:
                case 0x1F69:
                case 0x1F6A:
                case 0x1F6B:
                case 0x1F6C:
                case 0x1F6D:
                case 0x1F6E:
                case 0x1F6F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F59-U+1F6F
                    target[limit++] = ( char ) ( c - 0x0008 );
                    break;

                case 0x1F80:
                case 0x1F81:
                case 0x1F82:
                case 0x1F83:
                case 0x1F84:
                case 0x1F85:
                case 0x1F86:
                case 0x1F87:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F80-U+1F87
                    target[limit++] = ( char ) ( c - 0x0080 );
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F88:
                case 0x1F89:
                case 0x1F8A:
                case 0x1F8B:
                case 0x1F8C:
                case 0x1F8D:
                case 0x1F8E:
                case 0x1F8F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F88-U+1F8F
                    target[limit++] = ( char ) ( c - 0x0088 );
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F90:
                case 0x1F91:
                case 0x1F92:
                case 0x1F93:
                case 0x1F94:
                case 0x1F95:
                case 0x1F96:
                case 0x1F97:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F90-U+1F97
                    target[limit++] = ( char ) ( c - 0x0070 );
                    target[limit++] = 0x03B9;
                    break;

                case 0x1F98:
                case 0x1F99:
                case 0x1F9A:
                case 0x1F9B:
                case 0x1F9C:
                case 0x1F9D:
                case 0x1F9E:
                case 0x1F9F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F98-U+1F9F
                    target[limit++] = ( char ) ( c - 0x0078 );
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FA0:
                case 0x1FA1:
                case 0x1FA2:
                case 0x1FA3:
                case 0x1FA4:
                case 0x1FA5:
                case 0x1FA6:
                case 0x1FA7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FA0-U+1FA7
                    target[limit++] = ( char ) ( c - 0x0040 );
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FA8:
                case 0x1FA9:
                case 0x1FAA:
                case 0x1FAB:
                case 0x1FAC:
                case 0x1FAD:
                case 0x1FAE:
                case 0x1FAF:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FA8-U+1FAF
                    target[limit++] = ( char ) ( c - 0x0048 );
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FB2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FB2
                    target[limit++] = 0x1F70;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FB3:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FB3
                    target[limit++] = 0x03B1;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FB4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FB4
                    target[limit++] = 0x03AC;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FB6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FB6
                    target[limit++] = 0x03B1;
                    target[limit++] = 0x0342;
                    break;

                case 0x1FB7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FB7
                    target[limit++] = 0x03B1;
                    target[limit++] = 0x0342;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FB8:
                case 0x1FB9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FB8,U+1FB9
                    target[limit++] = ( char ) ( c - 0x0008 );
                    break;

                case 0x1FBA:
                case 0x1FBB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FBA,U+1FBB
                    target[limit++] = ( char ) ( c - 0x004A );
                    target[limit++] = 0x1F70;
                    break;

                case 0x1FBC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FBC
                    target[limit++] = 0x03B1;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FBE:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FBE
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FC2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FC2
                    target[limit++] = 0x1F74;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FC3:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FC3
                    target[limit++] = 0x03B7;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FC4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FC4
                    target[limit++] = 0x03AE;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FC6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FC6
                    target[limit++] = 0x03B7;
                    target[limit++] = 0x0342;
                    break;

                case 0x1FC7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FC7
                    target[limit++] = 0x03B7;
                    target[limit++] = 0x0342;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FC8:
                case 0x1FC9:
                case 0x1FCA:
                case 0x1FCB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FC8-U+01FCB
                    target[limit++] = ( char ) ( c - 0x0056 );
                    target[limit++] = 0x1F72;
                    break;

                case 0x1FCC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FCC
                    target[limit++] = 0x03B7;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FD2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FD2
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0300;
                    break;

                case 0x1FD3:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FD3
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0301;
                    break;

                case 0x1FD6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FD6
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0342;
                    break;

                case 0x1FD7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FD7
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0342;
                    break;

                case 0x1FD8:
                case 0x1FD9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FD8-U+01FD9
                    target[limit++] = ( char ) ( c - 0x0008 );
                    break;

                case 0x1FDA:
                case 0x1FDB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FD8-U+01FD9
                    target[limit++] = ( char ) ( c - 0x0064 );
                    break;

                case 0x1FE2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FE2
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0300;
                    break;

                case 0x1FE3:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FE3
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0301;
                    break;

                case 0x1FE4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FE4
                    target[limit++] = 0x03C1;
                    target[limit++] = 0x0313;
                    break;

                case 0x1FE6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FE6
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0342;
                    break;

                case 0x1FE7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FE7
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0342;
                    break;

                case 0x1FE8:
                case 0x1FE9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FE8-U+01FE9
                    target[limit++] = ( char ) ( c - 0x0008 );
                    break;

                case 0x1FEA:
                case 0x1FEB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FEA-U+01FEB
                    target[limit++] = ( char ) ( c - 0x0070 );
                    break;

                case 0x1FEC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FEC
                    target[limit++] = 0x1FE5;
                    break;

                case 0x1FF2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FF2
                    target[limit++] = 0x1F7C;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FF3:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FF3
                    target[limit++] = 0x03C9;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FF4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FF4
                    target[limit++] = 0x03CE;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FF6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FF6
                    target[limit++] = 0x03C9;
                    target[limit++] = 0x0342;
                    break;

                case 0x1FF7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FF7
                    target[limit++] = 0x03C9;
                    target[limit++] = 0x0342;
                    target[limit++] = 0x03B9;
                    break;

                case 0x1FF8:
                case 0x1FF9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FF8-U+01FF9
                    target[limit++] = ( char ) ( c - 0x0080 );
                    break;

                case 0x1FFA:
                case 0x1FFB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FFA-U+01FFB
                    target[limit++] = ( char ) ( c - 0x007E );
                    target[limit++] = 0x1F7C;
                    break;

                case 0x1FFC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FFC
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
                    // All other code points with Separator (space, line, or paragraph) property 
                    // (e.g., Zs, Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
                    //  list of these code points: ...2000-200A...
                    target[limit++] = 0x0020;
                    break;

                case 0x200B:
                    // ZERO WIDTH SPACE (U+200B) is mapped to nothing.
                        break;
                    
                case 0x200C:
                case 0x200D:
                case 0x200E:
                case 0x200F:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+200C-200FF...
                    break;

                case 0x2028:
                case 0x2029:
                    // All other code points with Separator (space, line, or paragraph) property 
                    // (e.g., Zs, Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
                    //  list of these code points: ... 2028-2029...
                    target[limit++] = 0x0020;
                    break;

                case 0x202A:
                case 0x202B:
                case 0x202C:
                case 0x202D:
                case 0x202E:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+202A-202E...
                    break;

                case 0x202F:
                    // All other code points with Separator (space, line, or paragraph) property 
                    // (e.g., Zs, Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
                    //  list of these code points: ... 202F ...
                    target[limit++] = 0x0020;
                    break;

                case 0x205F:
                    // All other code points with Separator (space, line, or paragraph) property 
                    // (e.g., Zs, Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
                    //  list of these code points:...205F...
                    target[limit++] = 0x0020;
                    break;

                case 0x2060:
                case 0x2061:
                case 0x2062:
                case 0x2063:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+2060-2063...
                    break;

                case 0x206A:
                case 0x206B:
                case 0x206C:
                case 0x206D:
                case 0x206E:
                case 0x206F:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+20GA-20GFF...
                    break;

                case 0x20A8:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+20A8
                    target[limit++] = 0x0072;
                    target[limit++] = 0x0073;
                    break;

                case 0x2102:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2102
                    target[limit++] = 0x0063;
                    break;

                case 0x2103:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2103
                    target[limit++] = 0x00B0;
                    target[limit++] = 0x0063;
                    break;

                case 0x2107:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2107
                    target[limit++] = 0x025B;
                    break;

                case 0x2109:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2109
                    target[limit++] = 0x00B0;
                    target[limit++] = 0x0066;
                    break;

                case 0x210B:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+210B
                    target[limit++] = 0x0068;
                    break;

                case 0x210C:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+210C
                    target[limit++] = 0x0068;
                    break;

                case 0x210D:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+210D
                    target[limit++] = 0x0068;
                    break;

                case 0x2110:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2110
                    target[limit++] = 0x0069;
                    break;

                case 0x2111:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2111
                    target[limit++] = 0x0069;
                    break;

                case 0x2112:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2112
                    target[limit++] = 0x006C;
                    break;

                case 0x2115:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2115
                    target[limit++] = 0x006E;
                    break;

                case 0x2116:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2116
                    target[limit++] = 0x006E;
                    target[limit++] = 0x006F;
                    break;

                case 0x2119:
                case 0x211A:
                case 0x211B:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2119-U+211B
                    target[limit++] = ( char ) ( c - 0x2A09 );
                    break;

                case 0x211C:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+211C
                    target[limit++] = 0x0072;
                    break;

                case 0x211D:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+211D
                    target[limit++] = 0x0072;
                    break;

                case 0x2120:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2120
                    target[limit++] = 0x0073;
                    target[limit++] = 0x006D;
                    break;

                case 0x2121:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2121
                    target[limit++] = 0x0074;
                    target[limit++] = 0x0065;
                    target[limit++] = 0x006C;
                    break;

                case 0x2122:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2122
                    target[limit++] = 0x0074;
                    target[limit++] = 0x006D;
                    break;

                case 0x2124:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2122
                    target[limit++] = 0x007A;
                    break;

                case 0x2126:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2122
                    target[limit++] = 0x03C9;
                    break;

                case 0x2128:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2122
                    target[limit++] = 0x007A;
                    break;

                case 0x212A:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2122
                    target[limit++] = 0x006B;
                    break;

                case 0x212B:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2122
                    target[limit++] = 0x00E5;
                    break;

                case 0x212C:
                case 0x212D:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+212C-U+212D
                    target[limit++] = ( char ) ( c - 0x20CA );
                    break;

                case 0x2130:
                case 0x2131:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2130-U+2131
                    target[limit++] = ( char ) ( c - 0x20CB );
                    break;

                case 0x2133:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2133
                    target[limit++] = 0x006D;
                    break;

                case 0x213E:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+213E
                    target[limit++] = 0x03B3;
                    break;

                case 0x213F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+213F
                    target[limit++] = 0x03C0;
                    break;

                case 0x2145:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2145
                    target[limit++] = 0x0064;
                    break;

                case 0x2160:
                case 0x2161:
                case 0x2162:
                case 0x2163:
                case 0x2164:
                case 0x2165:
                case 0x2166:
                case 0x2167:
                case 0x2168:
                case 0x2169:
                case 0x216A:
                case 0x216B:
                case 0x216C:
                case 0x216D:
                case 0x216E:
                case 0x216F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2160-U+216F
                    target[limit++] = ( char ) ( c + 0x0010 );
                    break;

                case 0x24B6:
                case 0x24B7:
                case 0x24B8:
                case 0x24B9:
                case 0x24BA:
                case 0x24BB:
                case 0x24BC:
                case 0x24BD:
                case 0x24BE:
                case 0x24BF:
                case 0x24C0:
                case 0x24C1:
                case 0x24C2:
                case 0x24C3:
                case 0x24C4:
                case 0x24C5:
                case 0x24C6:
                case 0x24C7:
                case 0x24C8:
                case 0x24C9:
                case 0x24CA:
                case 0x24CB:
                case 0x24CC:
                case 0x24CD:
                case 0x24CE:
                case 0x24CF:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+24B6-U+24CF
                    target[limit++] = ( char ) ( c + 0x001A );
                    break;

                case 0x3000:
                    // All other code points with Separator (space, line, or paragraph) property 
                    // (e.g., Zs, Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
                    //  list of these code points: ...3000.
                    target[limit++] = 0x0020;
                    break;

                case 0x3371:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3371
                    target[limit++] = 0x0068;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;

                case 0x3373:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3373
                    target[limit++] = 0x0061;
                    target[limit++] = 0x0075;
                    break;

                case 0x3375:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3375
                    target[limit++] = 0x006F;
                    target[limit++] = 0x0076;
                    break;

                case 0x3380:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3380
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;

                case 0x3381:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3381
                    target[limit++] = 0x006E;
                    target[limit++] = 0x0061;
                    break;

                case 0x3382:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3382
                    target[limit++] = 0x03BC;
                    target[limit++] = 0x0061;
                    break;

                case 0x3383:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3383
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0061;
                    break;

                case 0x3384:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3384
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0061;
                    break;

                case 0x3385:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3385
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0062;
                    break;

                case 0x3386:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3386
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0062;
                    break;

                case 0x3387:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3387
                    target[limit++] = 0x0067;
                    target[limit++] = 0x0062;
                    break;

                case 0x338A:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+338A
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0066;
                    break;

                case 0x338B:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+338B
                    target[limit++] = 0x006E;
                    target[limit++] = 0x0066;
                    break;

                case 0x338C:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+338C
                    target[limit++] = 0x03BC;
                    target[limit++] = 0x0066;
                    break;

                case 0x3390:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3390
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;

                case 0x3391:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3391
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;

                case 0x3392:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3392
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;

                case 0x3393:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3393
                    target[limit++] = 0x0067;
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;

                case 0x3394:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3394
                    target[limit++] = 0x0074;
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;

                case 0x33A9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33A9
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;

                case 0x33AA:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33AA
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;

                case 0x33AB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33AB
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;

                case 0x33AC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33AC
                    target[limit++] = 0x0067;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;

                case 0x33B4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33B4
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0076;
                    break;

                case 0x33B5:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33B5
                    target[limit++] = 0x006E;
                    target[limit++] = 0x0076;
                    break;

                case 0x33B6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33B6
                    target[limit++] = 0x03BC;
                    target[limit++] = 0x0076;
                    break;

                case 0x33B7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33B7
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0076;
                    break;

                case 0x33B8:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33B8
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0076;
                    break;

                case 0x33B9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33B9
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0076;
                    break;

                case 0x33BA:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33BA
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0077;
                    break;

                case 0x33BB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33BB
                    target[limit++] = 0x006E;
                    target[limit++] = 0x0077;
                    break;

                case 0x33BC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33BC
                    target[limit++] = 0x03BC;
                    target[limit++] = 0x0077;
                    break;

                case 0x33BD:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33BD
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0077;
                    break;

                case 0x33BE:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33BE
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0077;
                    break;

                case 0x33BF:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33BF
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0077;
                    break;

                case 0x33C0:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33C0
                    target[limit++] = 0x006B;
                    target[limit++] = 0x03C9;
                    break;

                case 0x33C1:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33C1
                    target[limit++] = 0x006D;
                    target[limit++] = 0x03C9;
                    break;

                case 0x33C3:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33C3
                    target[limit++] = 0x0062;
                    target[limit++] = 0x0071;
                    break;

                case 0x33C6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33C6
                    target[limit++] = 0x0063;
                    target[limit++] = 0x2215;
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0067;
                    break;

                case 0x33C7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33C7
                    target[limit++] = 0x0063;
                    target[limit++] = 0x006F;
                    target[limit++] = 0x002E;
                    break;

                case 0x33C8:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33C8
                    target[limit++] = 0x0064;
                    target[limit++] = 0x0062;
                    break;

                case 0x33C9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33C9
                    target[limit++] = 0x0067;
                    target[limit++] = 0x0079;
                    break;

                case 0x33CB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33CB
                    target[limit++] = 0x0068;
                    target[limit++] = 0x0070;
                    break;

                case 0x33CD:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33CD
                    target[limit++] = 0x006B;
                    target[limit++] = 0x006B;
                    break;

                case 0x33CE:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33CE
                    target[limit++] = 0x006B;
                    target[limit++] = 0x006D;
                    break;

                case 0x33D7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33D7
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0068;
                    break;

                case 0x33D9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33D9
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x006D;
                    break;

                case 0x33DA:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33DA
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0072;
                    break;

                case 0x33DC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33DC
                    target[limit++] = 0x0073;
                    target[limit++] = 0x0076;
                    break;

                case 0x33DD:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33DD
                    target[limit++] = 0x0077;
                    target[limit++] = 0x0062;
                    break;

                case 0xFB00:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB00
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0066;
                    break;

                case 0xFB01:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB01
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0069;
                    break;

                case 0xFB02:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB02
                    target[limit++] = 0x0066;
                    target[limit++] = 0x006C;
                    break;

                case 0xFB03:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB03
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0069;
                    break;

                case 0xFB04:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB04
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0066;
                    target[limit++] = 0x006C;
                    break;

                case 0xFB05:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB05
                    target[limit++] = 0x0073;
                    target[limit++] = 0x0074;
                    break;

                case 0xFB06:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB06
                    target[limit++] = 0x0073;
                    target[limit++] = 0x0074;
                    break;

                case 0xFB13:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB13
                    target[limit++] = 0x0574;
                    target[limit++] = 0x0576;
                    break;

                case 0xFB14:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB14
                    target[limit++] = 0x0574;
                    target[limit++] = 0x0565;
                    break;

                case 0xFB15:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB15
                    target[limit++] = 0x0574;
                    target[limit++] = 0x056B;
                    break;

                case 0xFB16:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB16
                    target[limit++] = 0x057E;
                    target[limit++] = 0x0576;
                    break;

                case 0xFB17:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB17
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
                    // SOFT HYPHEN (U+00AD) and MONGOLIAN TODO SOFT HYPHEN (U+1806) code
                    // points are mapped to nothing.  COMBINING GRAPHEME JOINER (U+034F) and
                    // VARIATION SELECTORs (U+180B-180D, FE00-FE0F) code points are also
                    // mapped to nothing.  The OBJECT REPLACEMENT CHARACTER (U+FFFC) is
                    // mapped to nothing.
                    break;

                case 0xFEFF:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+FEFF...
                    break;

                case 0xFF21:
                case 0xFF22:
                case 0xFF23:
                case 0xFF24:
                case 0xFF25:
                case 0xFF26:
                case 0xFF27:
                case 0xFF28:
                case 0xFF29:
                case 0xFF2A:
                case 0xFF2B:
                case 0xFF2C:
                case 0xFF2D:
                case 0xFF2E:
                case 0xFF2F:
                case 0xFF30:
                case 0xFF31:
                case 0xFF32:
                case 0xFF33:
                case 0xFF34:
                case 0xFF35:
                case 0xFF36:
                case 0xFF37:
                case 0xFF38:
                case 0xFF39:
                case 0xFF3A:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FF21-FF3A
                    target[limit++] = ( char ) ( c + 0x0020 );
                    break;

                case 0xFFF9:
                case 0xFFFA:
                case 0xFFFB:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+FFF9-FFFB...
                    break;
                    
                case 0xFFFC:
                    // SOFT HYPHEN (U+00AD) and MONGOLIAN TODO SOFT HYPHEN (U+1806) code
                    // points are mapped to nothing.  COMBINING GRAPHEME JOINER (U+034F) and
                    // VARIATION SELECTORs (U+180B-180D, FF00-FE0F) code points are also
                    // mapped to nothing.  The OBJECT REPLACEMENT CHARACTER (U+FFFC) is
                    // mapped to nothing.
                    break;

                default:
                    // First, eliminate surrogates, and replace them by FFFD char
                    if ( ( c >= 0xD800 ) && ( c <= 0xDFFF ) )
                    {
                        target[limit++] = 0xFFFD;
                        break;
                    }

                    target[limit++] = c;
                    break;
            }
        }

        return new String( target, 0, limit );
    }


    /**
     * Check that the String does not contain any prohibited char
     *
     * @param value The String to analyze
     * @throws InvalidCharacterException If any character is prohibited
     */
    public static void checkProhibited( char[] value ) throws InvalidCharacterException
    {
        for ( char c : value )
        {
            checkProhibited( c );
        }
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
     * Remove all insignificant spaces in a numeric string. For
     * instance, the following numeric string :
     * "  123  456  789  "
     * will be transformed to :
     * "123456789"
     *
     * @param source The numeric String
     * @return The modified numeric String
     */
    public static String insignificantNumericStringHandling( char[] source )
    {
        int pos = 0;

        for ( char c : source )
        {
            if ( c != 0x20 )
            {
                source[pos++] = c;
            }
        }

        return new String( source, 0, pos );
    }


    /**
     * Remove all insignificant spaces in a TelephoneNumber string,
     * Hyphen and spaces. 
     * 
     * For instance, the following telephone number :
     * "+ (33) 1-123--456  789"
     * will be transformed to :
     * "+(33)1123456789"
     *
     * @param source The telephoneNumber String
     * @return The modified telephoneNumber String
     */
    public static String insignificantTelephoneNumberStringHandling( char[] source )
    {
        if ( source == null )
        {
            return null;
        }

        int pos = 0;

        for ( char c : source )
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
                    break;

                default:
                    source[pos++] = c;
                    break;
            }
        }

        return new String( source, 0, pos );
    }


    /**
     * Remove all insignificant spaces in a string. Any resulting String will start 
     * with a space, ands with a space and every spaces found in the middle of the String
     * will be aggregated into two consecutive spaces :
     * 
     * <ul>
     * <li>empty string --&gt; &lt;space&gt;&lt;space&gt; </li>
     * <li>A --&gt; &lt;space&gt;A&lt;space&gt; </li>
     * <li>&lt;space&gt;A --&gt; &lt;space&gt;A&lt;space&gt; </li>
     * <li>&lt;space&gt;&lt;space&gt;A --&gt; &lt;space&gt;A&lt;space&gt; </li>
     * <li>A&lt;space&gt; --&gt; &lt;space&gt;A&lt;space&gt; </li>
     * <li>A&lt;space&gt;&lt;space&gt;&lt;space&gt;B --&gt; &lt;space&gt;A&lt;space&gt;&lt;space&gt;B&lt;space&gt; </li>
     * </ul>
     * This method use a finite state machine to parse the text.
     * 
     * @param origin The String to modify
     * @return The modified String
     * @throws InvalidCharacterException If an invalid character is met
     */
    public static String insignificantSpacesStringValue( char[] origin )
        throws InvalidCharacterException
    {
        if ( origin == null )
        {
            // Special case : a null strings is replaced by 2 spaces
            return "  ";
        }

        int pos = 0;

        // Create a target char array which is longer than the original String, as we will
        // have 2 more spaces (one at the beginning, one at the end, and each space in the 
        // middle will be doubled).
        int newPos = 0;
        
        /*
        boolean spaceSeen = false;
        int i = 0;
        
        for ( i = 0; i < origin.length; i++ )
        {
            if ( origin[i] != ' ' )
            {
                break;
            }
        }
        
        if ( i == origin.length )
        {
            return "  ";
        }

        char[] target = new char[origin.length * 2 + 1];
        target[newPos++] = ' ';
        
        for ( ; i < origin.length; i++ )
        {
            if ( origin[i] == ' ' )
            {
                spaceSeen = true;
                continue;
            }
            else if ( spaceSeen )
            {
                spaceSeen = false;
                target[newPos++] = ' ';
                target[newPos++] = ' ';
            }
            
            target[newPos++] = origin[i];
        }
        
        target[newPos++] = ' ';
        
        return new String( target, 0, newPos );
        */
        
        char[] target = new char[origin.length * 2 + 1];
        NormStateEnum normState = NormStateEnum.START;
        
        while ( normState != NormStateEnum.END )
        {
            switch ( normState )
            {
                case START :
                    if ( pos == origin.length )
                    {
                        // We are done, it's an empty string
                        return "  ";
                    }
                    
                    char c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        normState = NormStateEnum.INITIAL_SPACES;
                    }
                    else
                    {
                        // First add a space
                        target[newPos++] = ' ';
                        
                        // Then the char
                        target[newPos++] = c;
                        
                        pos++;
                        normState = NormStateEnum.INITIAL_CHAR;
                    }
                    
                    break;
                    
                case INITIAL_CHAR :
                    if ( pos == origin.length )
                    {
                        // We are done, add a space
                        target[newPos++] = ' ';
                        normState = NormStateEnum.END;
                        
                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        // Switch to the SPACES state
                        pos++;
                        normState = NormStateEnum.SPACES;
                    }
                    else
                    {
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        normState = NormStateEnum.CHARS;
                    }
                    
                    break;

                case INITIAL_SPACES :
                    if ( pos == origin.length )
                    {
                        // We are done, this is an empty String
                        return "  ";
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        // Keep going with the current state
                    }
                    else
                    {
                        // Add a space
                        target[newPos++] = ' ';
                        
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        normState = NormStateEnum.INITIAL_CHAR;
                    }
                    
                    break;

                case CHARS :
                    if ( pos == origin.length )
                    {
                        // We are done, add a Space
                        target[newPos++] = ' ';
                        normState = NormStateEnum.END;
                        
                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        normState = NormStateEnum.SPACES;
                    }
                    else
                    {
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        // We keep going on the same state
                    }
                    
                    break;

                case SPACES :
                    if ( pos == origin.length )
                    {
                        // We are done, add a Space
                        target[newPos++] = ' ';
                        normState = NormStateEnum.END;

                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        // We keep going on the same state
                    }
                    else
                    {
                        // Add the two spaces
                        target[newPos++] = ' ';
                        target[newPos++] = ' ';
                        
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        
                        // Switch to SPACE_CHAR state
                        normState = NormStateEnum.SPACE_CHAR;
                    }
                    
                    break;

                case SPACE_CHAR :
                    if ( pos == origin.length )
                    {
                        // We are done, add a Space
                        target[newPos++] = ' ';
                        normState = NormStateEnum.END;

                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        
                        // Switch to Spaces state
                        normState = NormStateEnum.SPACES;
                    }
                    else
                    {
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        
                        // Switch to CHARS state
                        normState = NormStateEnum.CHARS;
                    }
                    
                    break;
                    
                default :
                    // Do nothing
                    break;
            }
        }

        // create the resulting String
        return new String( target, 0, newPos );
    }
    
    
    /**
     * Remove all insignificant spaces in a Initial assertion. A String will always start 
     * with one space, every space in the middle will be doubled and if there are spaces
     * at the end, they will be replaced by one space :
     * <ul>
     * <li>A --&gt; &lt;space&gt;A </li>
     * <li>&lt;space&gt;A --&gt; &lt;space&gt;A </li>
     * <li>&lt;space&gt;&lt;space&gt;A --&gt; &lt;space&gt;A </li>
     * <li>A&lt;space&gt; --&gt; &lt;space&gt;A&lt;space&gt; </li>
     * <li>A&lt;space&gt;B --&gt; &lt;space&gt;A&lt;space&gt;&lt;space&gt;B </li>
     * </ul>
     * 
     * This method use a finite state machine to parse the text.
     * 
     * @param origin The String to modify
     * @return The modified String
     * @throws InvalidCharacterException If an invalid character is met
     */
    public static String insignificantSpacesStringInitial( char[] origin )
        throws InvalidCharacterException
    {
        if ( origin == null )
        {
            // Special case : a null string is replaced by 1 space
            return " ";
        }

        int pos = 0;

        // Create a target char array which is longer than the original String, as we will
        // have 1 more spaces (one at the beginning, one at the end, and each space in the 
        // middle will be doubled).
        char[] target = new char[origin.length * 2];
        int newPos = 0;
        
        NormStateEnum normState = NormStateEnum.START;
        
        while ( normState != NormStateEnum.END )
        {
            switch ( normState )
            {
                case START :
                    if ( pos == origin.length )
                    {
                        // We are done, it's an empty string
                        return " ";
                    }
                    
                    char c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        normState = NormStateEnum.INITIAL_SPACES;
                    }
                    else
                    {
                        // First add a space
                        target[newPos++] = ' ';
                        
                        // Then the char
                        target[newPos++] = c;
                        
                        pos++;
                        normState = NormStateEnum.INITIAL_CHAR;
                    }
                    
                    break;
                    
                case INITIAL_CHAR :
                    if ( pos == origin.length )
                    {
                        // We are done
                        normState = NormStateEnum.END;
                        
                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        // Switch to the SPACES state
                        pos++;
                        normState = NormStateEnum.SPACES;
                    }
                    else
                    {
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        normState = NormStateEnum.CHARS;
                    }
                    
                    break;

                case INITIAL_SPACES :
                    if ( pos == origin.length )
                    {
                        // We are done, this is an empty String
                        return " ";
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        // Keep going with the current state
                    }
                    else
                    {
                        // Add a space
                        target[newPos++] = ' ';
                        
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        normState = NormStateEnum.INITIAL_CHAR;
                    }
                    
                    break;

                case CHARS :
                    if ( pos == origin.length )
                    {
                        // We are done
                        normState = NormStateEnum.END;
                        
                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        normState = NormStateEnum.SPACES;
                    }
                    else
                    {
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        // We keep going on the same state
                    }
                    
                    break;

                case SPACES :
                    if ( pos == origin.length )
                    {
                        // We are done, add a Space
                        target[newPos++] = ' ';
                        normState = NormStateEnum.END;

                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        // We keep going on the same state
                    }
                    else
                    {
                        // Add the two spaces
                        target[newPos++] = ' ';
                        target[newPos++] = ' ';
                        
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        
                        // Switch to SPACE_CHAR state
                        normState = NormStateEnum.SPACE_CHAR;
                    }
                    
                    break;

                case SPACE_CHAR :
                    if ( pos == origin.length )
                    {
                        // We are done
                        normState = NormStateEnum.END;

                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        
                        // Switch to Spaces state
                        normState = NormStateEnum.SPACES;
                    }
                    else
                    {
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        
                        // Switch to CHARS state
                        normState = NormStateEnum.CHARS;
                    }
                    
                    break;
                    
                default :
                    // Do nothing
                    break;
            }
        }

        // create the resulting String
        return new String( target, 0, newPos );
    }

    
    /**
     * Remove all insignificant spaces in a Any assertion. A String starting with spaces 
     * will start with exactly one space, every space in the middle will be doubled and if 
     * there are spaces at the end, they will be replaced by one space :
     * <ul>
     * <li>A --&gt; A </li>
     * <li>&lt;space&gt;A --&gt; &lt;space&gt;A </li>
     * <li>&lt;space&gt;&lt;space&gt;A --&gt; &lt;space&gt;A </li>
     * <li>A&lt;space&gt; --&gt; A&lt;space&gt; </li>
     * <li>A&lt;space&gt;&lt;space&gt; --&gt; A&lt;space&gt; </li>
     * <li>A&lt;space&gt;B --&gt; A&lt;space&gt;&lt;space&gt;B </li>
     * </ul>
     *
     * This method use a finite state machine to parse
     * the text.
     * 
     * @param origin The String to modify
     * @return The modified String
     * @throws InvalidCharacterException If an invalid character is met
     */
    public static String insignificantSpacesStringAny( char[] origin )
        throws InvalidCharacterException
    {
        if ( origin == null )
        {
            // Special case : a null strings is replaced by 1 space
            return " ";
        }

        int pos = 0;

        // Create a target char array which is longer than the original String, as we may have to add a space.
        char[] target = new char[origin.length * 2 + 1];
        int newPos = 0;
        
        NormStateEnum normState = NormStateEnum.START;
        
        while ( normState != NormStateEnum.END )
        {
            switch ( normState )
            {
                case START :
                    if ( pos == origin.length )
                    {
                        // We are done, it's an empty string -> one space
                        return " ";
                    }
                    
                    char c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        normState = NormStateEnum.INITIAL_SPACES;
                    }
                    else
                    {
                        // Add the char
                        target[newPos++] = c;
                        
                        pos++;
                        normState = NormStateEnum.INITIAL_CHAR;
                    }
                    
                    break;
                    
                case INITIAL_CHAR :
                    if ( pos == origin.length )
                    {
                        // We are done
                        normState = NormStateEnum.END;
                        
                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        // Switch to the SPACES state, add a space in the target
                        target[newPos++] = ' ';
                        pos++;
                        normState = NormStateEnum.SPACES;
                    }
                    else
                    {
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        normState = NormStateEnum.CHARS;
                    }
                    
                    break;

                case INITIAL_SPACES :
                    if ( pos == origin.length )
                    {
                        // We are done, this is an empty String -> one space
                        return " ";
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        // Keep going with the current state
                    }
                    else
                    {
                        // Add a space
                        target[newPos++] = ' ';
                        
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        normState = NormStateEnum.INITIAL_CHAR;
                    }
                    
                    break;

                case CHARS :
                    if ( pos == origin.length )
                    {
                        // We are done
                        normState = NormStateEnum.END;
                        
                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        // Add the space
                        target[newPos++] = ' ';
                        
                        pos++;
                        normState = NormStateEnum.SPACES;
                    }
                    else
                    {
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        // We keep going on the same state
                    }
                    
                    break;

                case SPACES :
                    if ( pos == origin.length )
                    {
                        // We are done
                        normState = NormStateEnum.END;

                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        // We keep going on the same state
                    }
                    else
                    {
                        // Add the second space
                        target[newPos++] = ' ';
                        
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        
                        // Switch to SPACE_CHAR state
                        normState = NormStateEnum.SPACE_CHAR;
                    }
                    
                    break;

                case SPACE_CHAR :
                    if ( pos == origin.length )
                    {
                        // We are done
                        normState = NormStateEnum.END;

                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;

                        // Add the space
                        target[newPos++] = ' ';
                        
                        // Switch to Spaces state
                        normState = NormStateEnum.SPACES;
                    }
                    else
                    {
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        
                        // Switch to CHARS state
                        normState = NormStateEnum.CHARS;
                    }
                    
                    break;
                    
                default :
                    // Do nothing
                    break;
            }
        }

        // create the resulting String
        return new String( target, 0, newPos );
    }
    
    
    /**
     * Remove all insignificant spaces in a string.
     * 
     * This method use a finite state machine to parse
     * the text.
     * 
     * @param origin The String to modify
     * @return The modified StringBuilder
     * @throws InvalidCharacterException If an invalid character is found in the String
     */
    public static String insignificantSpacesStringFinal( char[] origin )
        throws InvalidCharacterException
    {
        if ( origin == null )
        {
            // Special case : a null strings is replaced by 1 spaces
            return " ";
        }

        int pos = 0;

        // Create a target char array which is longer than the original String, as we will
        // have 2 more spaces (one at the beginning, one at the end, and each space in the 
        // middle will be doubled).
        char[] target = new char[origin.length * 2 + 1];
        int newPos = 0;
        
        NormStateEnum normState = NormStateEnum.START;
        
        while ( normState != NormStateEnum.END )
        {
            switch ( normState )
            {
                case START :
                    if ( pos == origin.length )
                    {
                        // We are done, it's an empty string
                        return " ";
                    }
                    
                    char c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        normState = NormStateEnum.INITIAL_SPACES;
                    }
                    else
                    {
                        // Add the char
                        target[newPos++] = c;
                        
                        pos++;
                        normState = NormStateEnum.INITIAL_CHAR;
                    }
                    
                    break;
                    
                case INITIAL_CHAR :
                    if ( pos == origin.length )
                    {
                        // We are done, add a space
                        target[newPos++] = ' ';
                        normState = NormStateEnum.END;
                        
                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        // Switch to the SPACES state
                        pos++;
                        normState = NormStateEnum.SPACES;
                    }
                    else
                    {
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        normState = NormStateEnum.CHARS;
                    }
                    
                    break;

                case INITIAL_SPACES :
                    if ( pos == origin.length )
                    {
                        // We are done, this is an empty String
                        return " ";
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        // Keep going with the current state
                    }
                    else
                    {
                        // Add a space
                        target[newPos++] = ' ';
                        
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        normState = NormStateEnum.INITIAL_CHAR;
                    }
                    
                    break;

                case CHARS :
                    if ( pos == origin.length )
                    {
                        // We are done, add a Space
                        target[newPos++] = ' ';
                        normState = NormStateEnum.END;
                        
                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        normState = NormStateEnum.SPACES;
                    }
                    else
                    {
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        // We keep going on the same state
                    }
                    
                    break;

                case SPACES :
                    if ( pos == origin.length )
                    {
                        // We are done, add a Space
                        target[newPos++] = ' ';
                        normState = NormStateEnum.END;

                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        // We keep going on the same state
                    }
                    else
                    {
                        // Add the two spaces
                        target[newPos++] = ' ';
                        target[newPos++] = ' ';
                        
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        
                        // Switch to SPACE_CHAR state
                        normState = NormStateEnum.SPACE_CHAR;
                    }
                    
                    break;

                case SPACE_CHAR :
                    if ( pos == origin.length )
                    {
                        // We are done, add a Space
                        target[newPos++] = ' ';
                        normState = NormStateEnum.END;

                        break;
                    }
                    
                    c = origin[pos];
                    
                    if ( c == ' ' )
                    {
                        pos++;
                        
                        // Switch to Spaces state
                        normState = NormStateEnum.SPACES;
                    }
                    else
                    {
                        // Add the char
                        target[newPos++] = c;
                        pos++;
                        
                        // Switch to CHARS state
                        normState = NormStateEnum.CHARS;
                    }
                    
                    break;
                    
                default :
                    // Do nothing
                    break;
            }
        }

        // create the resulting String
        return new String( target, 0, newPos );
    }

    
    /**
     * Map for Ascii String, case insensitive
     */
    private static String mapIgnoreCaseAscii( String unicode )
    {
        char[] source = unicode.toCharArray();
        int pos = 0;
        
        for ( char c : source )
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
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: U+0000-0008...
                    break;
    
                case 0x0009:
                case 0x000A:
                case 0x000B:
                case 0x000C:
                case 0x000D:
                    // CHARACTER TABULATION (U+0009), LINE FEED (LF) (U+000A), LINE
                    // TABULATION (U+000B), FORM FEED (FF) (U+000C), CARRIAGE RETURN (CR)
                    // (U+000D), ... are mapped to SPACE (U+0020).
                    source[pos++] = 0x0020;
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
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+000E-001F...
                    break;
    
                case 0x0020:
                case 0x0021:
                case 0x0022:
                case 0x0023:
                case 0x0024:
                case 0x0025:
                case 0x0026:
                case 0x0027:
                case 0x0028:
                case 0x0029:
                case 0x002A:
                case 0x002B:
                case 0x002C:
                case 0x002D:
                case 0x002E:
                case 0x002F:
                case 0x0030:
                case 0x0031:
                case 0x0032:
                case 0x0033:
                case 0x0034:
                case 0x0035:
                case 0x0036:
                case 0x0037:
                case 0x0038:
                case 0x0039:
                case 0x003A:
                case 0x003B:
                case 0x003C:
                case 0x003D:
                case 0x003E:
                case 0x003F:
                case 0x0040:
                    source[pos++] = c;
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
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0041-005A
                    source[pos++] = ( char ) ( c + 0x0020 );
                    break;

                case 0x005B:
                case 0x005C:
                case 0x005D:
                case 0x005E:
                case 0x005F:
                case 0x0060:
                case 0x0061:
                case 0x0062:
                case 0x0063:
                case 0x0064:
                case 0x0065:
                case 0x0066:
                case 0x0067:
                case 0x0068:
                case 0x0069:
                case 0x006A:
                case 0x006B:
                case 0x006C:
                case 0x006D:
                case 0x006E:
                case 0x006F:
                case 0x0070:
                case 0x0071:
                case 0x0072:
                case 0x0073:
                case 0x0074:
                case 0x0075:
                case 0x0076:
                case 0x0077:
                case 0x0078:
                case 0x0079:
                case 0x007A:
                case 0x007B:
                case 0x007C:
                case 0x007D:
                case 0x007E:
                    source[pos++] = c;
                    break;

                case 0x007F:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+007F-0084...
                    break;
                    
                default :
                    throw AIOOBE;
            }
        }
        
        return new String( source, 0, pos );
    }

    
    /**
     * Map for Ascii String, case sensitive
     */
    private static String mapCaseSensitiveAscii( String unicode )
    {
        char[] source = unicode.toCharArray();
        int pos = 0;
        
        for ( char c : source )
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
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: U+0000-0008...
                    break;
    
                case 0x0009:
                case 0x000A:
                case 0x000B:
                case 0x000C:
                case 0x000D:
                    // CHARACTER TABULATION (U+0009), LINE FEED (LF) (U+000A), LINE
                    // TABULATION (U+000B), FORM FEED (FF) (U+000C), CARRIAGE RETURN (CR)
                    // (U+000D), ... are mapped to SPACE (U+0020).
                    source[pos++] = 0x0020;
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
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+000E-001F...
                    break;
    
                case 0x0020:
                case 0x0021:
                case 0x0022:
                case 0x0023:
                case 0x0024:
                case 0x0025:
                case 0x0026:
                case 0x0027:
                case 0x0028:
                case 0x0029:
                case 0x002A:
                case 0x002B:
                case 0x002C:
                case 0x002D:
                case 0x002E:
                case 0x002F:
                case 0x0030:
                case 0x0031:
                case 0x0032:
                case 0x0033:
                case 0x0034:
                case 0x0035:
                case 0x0036:
                case 0x0037:
                case 0x0038:
                case 0x0039:
                case 0x003A:
                case 0x003B:
                case 0x003C:
                case 0x003D:
                case 0x003E:
                case 0x003F:
                case 0x0040:
                    source[pos++] = c;
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
                case 0x005B:
                case 0x005C:
                case 0x005D:
                case 0x005E:
                case 0x005F:
                case 0x0060:
                case 0x0061:
                case 0x0062:
                case 0x0063:
                case 0x0064:
                case 0x0065:
                case 0x0066:
                case 0x0067:
                case 0x0068:
                case 0x0069:
                case 0x006A:
                case 0x006B:
                case 0x006C:
                case 0x006D:
                case 0x006E:
                case 0x006F:
                case 0x0070:
                case 0x0071:
                case 0x0072:
                case 0x0073:
                case 0x0074:
                case 0x0075:
                case 0x0076:
                case 0x0077:
                case 0x0078:
                case 0x0079:
                case 0x007A:
                case 0x007B:
                case 0x007C:
                case 0x007D:
                case 0x007E:
                    source[pos++] = c;
                    break;

                case 0x007F:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+007F-0084...
                    break;
                    
                default :
                    throw AIOOBE;
            }
        }
        
        return new String( source, 0, pos );
    }

    
    /**
     * Apply the RFC 4518 MAP transformation, case insensitive
     * 
     * @param unicode The original String
     * @return The mapped String
     */
    public static String mapIgnoreCase( String unicode )
    {
        try
        {
            return mapIgnoreCaseAscii( unicode );
        }
        catch ( ArrayIndexOutOfBoundsException aioobe )
        {
            // There 
        }

        char[] source = unicode.toCharArray();
        
        // Create a target char array which is 3 times bigger than the original size. 
        // We have to do that because the map phase may transform a char to
        // three chars.
        // TODO : we have to find a way to prevent this waste of space.
        char[] target = new char[unicode.length() * 3 + 2];
    
        int limit = 0;
    
        for ( char c : source )
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
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: U+0000-0008...
                    break;
    
                case 0x0009:
                case 0x000A:
                case 0x000B:
                case 0x000C:
                case 0x000D:
                    // CHARACTER TABULATION (U+0009), LINE FEED (LF) (U+000A), LINE
                    // TABULATION (U+000B), FORM FEED (FF) (U+000C), CARRIAGE RETURN (CR)
                    // (U+000D), ... are mapped to SPACE (U+0020).
                    target[limit++] = 0x0020;
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
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+000E-001F...
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
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0041-005A
                    target[limit++] = ( char ) ( c + 0x0020 );
                    break;
    
                case 0x0061:
                case 0x0062:
                case 0x0063:
                case 0x0064:
                case 0x0065:
                case 0x0066:
                case 0x0067:
                case 0x0068:
                case 0x0069:
                case 0x006A:
                case 0x006B:
                case 0x006C:
                case 0x006D:
                case 0x006E:
                case 0x006F:
                case 0x0070:
                case 0x0071:
                case 0x0072:
                case 0x0073:
                case 0x0074:
                case 0x0075:
                case 0x0076:
                case 0x0077:
                case 0x0078:
                case 0x0079:
                case 0x007A:
                    target[limit++] = c;
                    break;

                case 0x007F:
                case 0x0080:
                case 0x0081:
                case 0x0082:
                case 0x0083:
                case 0x0084:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+007F-0084...
                    break;
    
                case 0x0085:
                    // ... and NEXT LINE (NEL) (U+0085) are mapped to SPACE (U+0020).
                    target[limit++] = 0x0020;
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
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+0086-009F...
                    break;
    
                case 0x00A0:
                    // All other code points with Separator (space, line, or paragraph) property 
                    // (e.g., Zs, Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
                    //  list of these code points: ... 00A0 ...
                    target[limit++] = 0x0020;
                    break;
    
                case 0x00AD:
                    // SOFT HYPHEN (U+00AD) and MONGOLIAN TODO SOFT HYPHEN (U+1806) code
                    // points are mapped to nothing.  COMBINING GRAPHEME JOINER (U+034F) and
                    // VARIATION SELECTORs (U+180B-180D, FF00-FE0F) code points are also
                    // mapped to nothing.  The OBJECT REPLACEMENT CHARACTER (U+FFFC) is
                    // mapped to nothing.
                    break;
    
                case 0x00B5:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+00B5
                    target[limit++] = 0x03BC;
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
                // no 0x00D7
                case 0x00D6:
                case 0x00D8:
                case 0x00D9:
                case 0x00DA:
                case 0x00DB:
                case 0x00DC:
                case 0x00DD:
                case 0x00DE:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+00C0-00D6,
                    // U+00D8-00DE
                    target[limit++] = ( char ) ( c + 0x0020 );
                    break;
    
                case 0x00DF:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+00DF
                    target[limit++] = 0x0073;
                    target[limit++] = 0x0073;
                    break;
    
                case 0x0100:
                case 0x0102:
                case 0x0104:
                case 0x0106:
                case 0x0108:
                case 0x010A:
                case 0x010C:
                case 0x010E:
                case 0x0110:
                case 0x0112:
                case 0x0114:
                case 0x0116:
                case 0x0118:
                case 0x011A:
                case 0x011C:
                case 0x011E:
                case 0x0120:
                case 0x0122:
                case 0x0124:
                case 0x0126:
                case 0x0128:
                case 0x012A:
                case 0x012C:
                case 0x012E:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0100-012E
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
                case 0x0130:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0130
                    target[limit++] = 0x0069;
                    target[limit++] = 0x0307;
                    break;
    
                case 0x0132:
                case 0x0134:
                case 0x0136:
                case 0x0139:
                case 0x013B:
                case 0x013D:
                case 0x013F:
                case 0x0141:
                case 0x0143:
                case 0x0145:
                case 0x0147:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0132-0147
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
                case 0x0149:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0149
                    target[limit++] = 0x02BC;
                    target[limit++] = 0x006E;
                    break;
    
                case 0x014A:
                case 0x014C:
                case 0x014E:
                case 0x0150:
                case 0x0152:
                case 0x0154:
                case 0x0156:
                case 0x0158:
                case 0x015A:
                case 0x015C:
                case 0x015E:
                case 0x0160:
                case 0x0162:
                case 0x0164:
                case 0x0166:
                case 0x0168:
                case 0x016A:
                case 0x016C:
                case 0x016E:
                case 0x0170:
                case 0x0172:
                case 0x0174:
                case 0x0176:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0141-0176
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
                case 0x0178:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0178
                    target[limit++] = 0x00FF;
                    break;
    
                case 0x0179:
                case 0x017B:
                case 0x017D:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0179-017D
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
                case 0x017F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+017F
                    target[limit++] = 0x0073;
                    break;
    
                case 0x0181:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0181
                    target[limit++] = 0x0253;
                    break;
    
                case 0x0182:
                case 0x0184:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0182, U+0x0184
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
                case 0x0186:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0186
                    target[limit++] = 0x0254;
                    break;
    
                case 0x0187:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0188
                    target[limit++] = 0x0188;
                    break;
    
                case 0x0189:
                case 0x018A:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0189, U+018A
                    target[limit++] = ( char ) ( c + 0x00CD );
                    break;
    
                case 0x018B:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+018B
                    target[limit++] = 0x018C;
                    break;
    
                case 0x018E:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+018E
                    target[limit++] = 0x01DD;
                    break;
    
                case 0x018F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+018F
                    target[limit++] = 0x0259;
                    break;
    
                case 0x0190:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0190
                    target[limit++] = 0x025B;
                    break;
    
                case 0x0191:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0191
                    target[limit++] = 0x0192;
                    break;
    
                case 0x0193:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0193
                    target[limit++] = 0x0260;
                    break;
    
                case 0x0194:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0194
                    target[limit++] = 0x0263;
                    break;
    
                case 0x0196:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0196
                    target[limit++] = 0x0269;
                    break;
    
                case 0x0197:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0197
                    target[limit++] = 0x0268;
                    break;
    
                case 0x0198:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0198
                    target[limit++] = 0x0199;
                    break;
    
                case 0x019C:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+019C
                    target[limit++] = 0x026F;
                    break;
    
                case 0x019D:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+019D
                    target[limit++] = 0x0272;
                    break;
    
                case 0x019F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+019F
                    target[limit++] = 0x0275;
                    break;
    
                case 0x01A0:
                case 0x01A2:
                case 0x01A4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01A0-U+01A4
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
                case 0x01A6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01A6
                    target[limit++] = 0x0280;
                    break;
    
                case 0x01A7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01A7
                    target[limit++] = 0x01A8;
                    break;
    
                case 0x01A9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01A9
                    target[limit++] = 0x0283;
                    break;
    
                case 0x01AC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01AC
                    target[limit++] = 0x01AD;
                    break;
    
                case 0x01AE:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01AE
                    target[limit++] = 0x0288;
                    break;
    
                case 0x01AF:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01AF
                    target[limit++] = 0x01B0;
                    break;
    
                case 0x01B1:
                case 0x01B2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01AF, U+01B2
                    target[limit++] = ( char ) ( c + 0x00D9 );
                    break;
    
                case 0x01B3:
                case 0x01B5:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01B3, U+01B5
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
                case 0x01B7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01B7
                    target[limit++] = 0x0292;
                    break;
    
                case 0x01B8:
                case 0x01BC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01B8, U+01BC
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
                case 0x01C4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01C4,U+01C5
                    target[limit++] = 0x01C6;
                    break;
    
                case 0x01C7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01C7,U+01C8
                    target[limit++] = 0x01C9;
                    break;
    
                case 0x01CA:
                case 0x01CB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01CA,U+01CB
                    target[limit++] = 0x01CC;
                    break;
    
                case 0x01CD:
                case 0x01CF:
                case 0x01D1:
                case 0x01D3:
                case 0x01D5:
                case 0x01D7:
                case 0x01D9:
                case 0x01DB:
                case 0x01DE:
                case 0x01E0:
                case 0x01E2:
                case 0x01E4:
                case 0x01E6:
                case 0x01E8:
                case 0x01EA:
                case 0x01EC:
                case 0x01EE:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01CD, U+01EE
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
                case 0x01F0:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01F0
                    target[limit++] = 0x006A;
                    target[limit++] = 0x030C;
                    break;
    
                case 0x01F1:
                case 0x01F2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01F1, U+01F2
                    target[limit++] = 0x01F3;
                    break;
    
                case 0x01F4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01F4
                    target[limit++] = 0x01F5;
                    break;
    
                case 0x01F6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01F6
                    target[limit++] = 0x0195;
                    break;
    
                case 0x01F7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01F7
                    target[limit++] = 0x01BF;
                    break;
    
                case 0x01F8:
                case 0x01FA:
                case 0x01FC:
                case 0x01FE:
                case 0x0200:
                case 0x0202:
                case 0x0204:
                case 0x0206:
                case 0x0208:
                case 0x020A:
                case 0x020C:
                case 0x020E:
                case 0x0210:
                case 0x0212:
                case 0x0214:
                case 0x0216:
                case 0x0218:
                case 0x021A:
                case 0x021C:
                case 0x021E:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+01F8-U+021E
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
    
                case 0x0220:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0220
                    target[limit++] = 0x019E;
                    break;
    
                case 0x0222:
                case 0x0224:
                case 0x0226:
                case 0x0228:
                case 0x022A:
                case 0x022C:
                case 0x022E:
                case 0x0230:
                case 0x0232:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0222-U+0232
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
                case 0x0345:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0220
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x034F:
                    // SOFT HYPHEN (U+00AD) and MONGOLIAN TODO SOFT HYPHEN (U+1806) code
                    // points are mapped to nothing.  COMBINING GRAPHEME JOINER (U+034F) and
                    // VARIATION SELECTORs (U+180B-180D, FF00-FE0F) code points are also
                    // mapped to nothing.  The OBJECT REPLACEMENT CHARACTER (U+FFFC) is
                    // mapped to nothing.
                    break;
    
                case 0x037A:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+037A
                    target[limit++] = 0x0020;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x0386:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0386
                    target[limit++] = 0x03AC;
                    break;
    
                case 0x0388:
                case 0x0389:
                case 0x038A:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0388, U+0389, U+038A
                    target[limit++] = ( char ) ( c + 0x0025 );
                    break;
    
                case 0x038C:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+038C
                    target[limit++] = 0x03CC;
                    break;
    
                case 0x038E:
                case 0x038F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+038E, U+038F
                    target[limit++] = ( char ) ( c + 0x0025 );
                    break;
    
                case 0x0390:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0390
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0301;
                    break;
    
                case 0x0391:
                case 0x0392:
                case 0x0393:
                case 0x0394:
                case 0x0395:
                case 0x0396:
                case 0x0397:
                case 0x0398:
                case 0x0399:
                case 0x039A:
                case 0x039B:
                case 0x039C:
                case 0x039D:
                case 0x039E:
                case 0x039F:
                case 0x03A0:
                case 0x03A1:
                case 0x03A3:
                case 0x03A4:
                case 0x03A5:
                case 0x03A6:
                case 0x03A7:
                case 0x03A8:
                case 0x03A9:
                case 0x03AA:
                case 0x03AB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0391-U+03AB
                    target[limit++] = ( char ) ( c + 0x0020 );
                    break;
    
    
                case 0x03B0:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03B0
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0301;
                    break;
    
                case 0x03C2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03C2
                    target[limit++] = 0x03C3;
                    break;
    
                case 0x03D0:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D0
                    target[limit++] = 0x03B2;
                    break;
    
                case 0x03D1:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D1
                    target[limit++] = 0x03B8;
                    break;
    
                case 0x03D2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D2
                    target[limit++] = 0x03C5;
                    break;
    
                case 0x03D3:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D3
                    target[limit++] = 0x03CD;
                    break;
    
                case 0x03D4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D4
                    target[limit++] = 0x03CB;
                    break;
    
                case 0x03D5:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D5
                    target[limit++] = 0x03C6;
                    break;
    
                case 0x03D6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D6
                    target[limit++] = 0x03C0;
                    break;
    
                case 0x03D8:
                case 0x03DA:
                case 0x03DC:
                case 0x03DE:
                case 0x03E0:
                case 0x03E2:
                case 0x03E4:
                case 0x03E6:
                case 0x03E8:
                case 0x03EA:
                case 0x03EC:
                case 0x03EE:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03D8-U+03EE
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
                case 0x03F0:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03F0
                    target[limit++] = 0x03BA;
                    break;
    
                case 0x03F1:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03F1
                    target[limit++] = 0x03C1;
                    break;
    
                case 0x03F2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03F2
                    target[limit++] = 0x03C3;
                    break;
    
                case 0x03F4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03F4
                    target[limit++] = 0x03B8;
                    break;
    
                case 0x03F5:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+03F5
                    target[limit++] = 0x03B5;
                    break;
    
                case 0x0400:
                case 0x0401:
                case 0x0402:
                case 0x0403:
                case 0x0404:
                case 0x0405:
                case 0x0406:
                case 0x0407:
                case 0x0408:
                case 0x0409:
                case 0x040A:
                case 0x040B:
                case 0x040C:
                case 0x040D:
                case 0x040E:
                case 0x040F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0400-U+040F
                    target[limit++] = ( char ) ( c + 0x0050 );
                    break;
    
                case 0x0410:
                case 0x0411:
                case 0x0412:
                case 0x0413:
                case 0x0414:
                case 0x0415:
                case 0x0416:
                case 0x0417:
                case 0x0418:
                case 0x0419:
                case 0x041A:
                case 0x041B:
                case 0x041C:
                case 0x041D:
                case 0x041E:
                case 0x041F:
                case 0x0420:
                case 0x0421:
                case 0x0422:
                case 0x0423:
                case 0x0424:
                case 0x0425:
                case 0x0426:
                case 0x0427:
                case 0x0428:
                case 0x0429:
                case 0x042A:
                case 0x042B:
                case 0x042C:
                case 0x042D:
                case 0x042E:
                case 0x042F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0410-U+042F
                    target[limit++] = ( char ) ( c + 0x0020 );
                    break;
    
                case 0x0460:
                case 0x0462:
                case 0x0464:
                case 0x0466:
                case 0x0468:
                case 0x046A:
                case 0x046C:
                case 0x046E:
                case 0x0470:
                case 0x0472:
                case 0x0474:
                case 0x0476:
                case 0x0478:
                case 0x047A:
                case 0x047C:
                case 0x047E:
                case 0x0480:
                case 0x048A:
                case 0x048C:
                case 0x048E:
                case 0x0490:
                case 0x0492:
                case 0x0494:
                case 0x0496:
                case 0x0498:
                case 0x049A:
                case 0x049C:
                case 0x049E:
                case 0x04A0:
                case 0x04A2:
                case 0x04A4:
                case 0x04A6:
                case 0x04A8:
                case 0x04AA:
                case 0x04AC:
                case 0x04AE:
                case 0x04B0:
                case 0x04B2:
                case 0x04B4:
                case 0x04B6:
                case 0x04B8:
                case 0x04BA:
                case 0x04BC:
                case 0x04BE:
                case 0x04C1:
                case 0x04C3:
                case 0x04C5:
                case 0x04C7:
                case 0x04C9:
                case 0x04CB:
                case 0x04CD:
                case 0x04D0:
                case 0x04D2:
                case 0x04D4:
                case 0x04D6:
                case 0x04D8:
                case 0x04DA:
                case 0x04DC:
                case 0x04DE:
                case 0x04E0:
                case 0x04E2:
                case 0x04E4:
                case 0x04E6:
                case 0x04E8:
                case 0x04EA:
                case 0x04EC:
                case 0x04EE:
                case 0x04F0:
                case 0x04F2:
                case 0x04F4:
                case 0x04F8:
                case 0x0500:
                case 0x0502:
                case 0x0504:
                case 0x0506:
                case 0x0508:
                case 0x050A:
                case 0x050C:
                case 0x050E:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0460-U+050E
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
                case 0x0531:
                case 0x0532:
                case 0x0533:
                case 0x0534:
                case 0x0535:
                case 0x0536:
                case 0x0537:
                case 0x0538:
                case 0x0539:
                case 0x053A:
                case 0x053B:
                case 0x053C:
                case 0x053D:
                case 0x053E:
                case 0x053F:
                case 0x0540:
                case 0x0541:
                case 0x0542:
                case 0x0543:
                case 0x0544:
                case 0x0545:
                case 0x0546:
                case 0x0547:
                case 0x0548:
                case 0x0549:
                case 0x054A:
                case 0x054B:
                case 0x054C:
                case 0x054D:
                case 0x054E:
                case 0x054F:
                case 0x0550:
                case 0x0551:
                case 0x0552:
                case 0x0553:
                case 0x0554:
                case 0x0555:
                case 0x0556:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0531-U+0556
                    target[limit++] = ( char ) ( c + 0x0030 );
                    break;
    
    
                case 0x0587:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+0587
                    target[limit++] = 0x0565;
                    target[limit++] = 0x0582;
                    break;
    
                case 0x06DD:
                case 0x070F:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+06DD-070F...
                    break;
    
                case 0x1680:
                    // All other code points with Separator (space, line, or paragraph) property 
                    // (e.g., Zs, Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
                    //  list of these code points: ...1680...
                    target[limit++] = 0x0020;
                    break;
    
                case 0x1806:
                    // SOFT HYPHEN (U+00AD) and MONGOLIAN TODO SOFT HYPHEN (U+1806) code
                    // points are mapped to nothing.  COMBINING GRAPHEME JOINER (U+034F) and
                    // VARIATION SELECTORs (U+180B-180D, FF00-FE0F) code points are also
                    // mapped to nothing.  The OBJECT REPLACEMENT CHARACTER (U+FFFC) is
                    // mapped to nothing.
                    break;
    
                case 0x180B:
                case 0x180C:
                case 0x180D:
                    // SOFT HYPHEN (U+00AD) and MONGOLIAN TODO SOFT HYPHEN (U+1806) code
                    // points are mapped to nothing.  COMBINING GRAPHEME JOINER (U+034F) and
                    // VARIATION SELECTORs (U+180B-180D, FF00-FE0F) code points are also
                    // mapped to nothing.  The OBJECT REPLACEMENT CHARACTER (U+FFFC) is
                    // mapped to nothing.
                    break;
                    
                case 0x180E:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+180E...
                    break;
    
                case 0x1E00:
                case 0x1E02:
                case 0x1E04:
                case 0x1E06:
                case 0x1E08:
                case 0x1E0A:
                case 0x1E0C:
                case 0x1E0E:
                case 0x1E10:
                case 0x1E12:
                case 0x1E14:
                case 0x1E16:
                case 0x1E18:
                case 0x1E1A:
                case 0x1E1C:
                case 0x1E1E:
                case 0x1E20:
                case 0x1E22:
                case 0x1E24:
                case 0x1E26:
                case 0x1E28:
                case 0x1E2A:
                case 0x1E2C:
                case 0x1E2E:
                case 0x1E30:
                case 0x1E32:
                case 0x1E34:
                case 0x1E36:
                case 0x1E38:
                case 0x1E3A:
                case 0x1E3C:
                case 0x1E3E:
                case 0x1E40:
                case 0x1E42:
                case 0x1E44:
                case 0x1E46:
                case 0x1E48:
                case 0x1E4A:
                case 0x1E4C:
                case 0x1E4E:
                case 0x1E50:
                case 0x1E52:
                case 0x1E54:
                case 0x1E56:
                case 0x1E58:
                case 0x1E5A:
                case 0x1E5C:
                case 0x1E5E:
                case 0x1E60:
                case 0x1E62:
                case 0x1E64:
                case 0x1E66:
                case 0x1E68:
                case 0x1E6A:
                case 0x1E6C:
                case 0x1E6E:
                case 0x1E70:
                case 0x1E72:
                case 0x1E74:
                case 0x1E76:
                case 0x1E78:
                case 0x1E7A:
                case 0x1E7C:
                case 0x1E7E:
                case 0x1E80:
                case 0x1E82:
                case 0x1E84:
                case 0x1E86:
                case 0x1E88:
                case 0x1E8A:
                case 0x1E8C:
                case 0x1E8E:
                case 0x1E90:
                case 0x1E92:
                case 0x1E94:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1E00-U+1E94
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
                case 0x1E96:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1E96
                    target[limit++] = 0x0068;
                    target[limit++] = 0x0331;
                    break;
    
                case 0x1E97:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1E97
                    target[limit++] = 0x0074;
                    target[limit++] = 0x0308;
                    break;
    
                case 0x1E98:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1E98
                    target[limit++] = 0x0077;
                    target[limit++] = 0x030A;
                    break;
    
                case 0x1E99:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1E99
                    target[limit++] = 0x0079;
                    target[limit++] = 0x030A;
                    break;
    
                case 0x1E9A:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1E9A
                    target[limit++] = 0x0061;
                    target[limit++] = 0x02BE;
                    break;
    
                case 0x1E9B:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1E9B
                    target[limit++] = 0x1E61;
                    break;
    
                case 0x1EA0:
                case 0x1EA2:
                case 0x1EA4:
                case 0x1EA6:
                case 0x1EA8:
                case 0x1EAA:
                case 0x1EAC:
                case 0x1EAE:
                case 0x1EB0:
                case 0x1EB2:
                case 0x1EB4:
                case 0x1EB6:
                case 0x1EB8:
                case 0x1EBA:
                case 0x1EBC:
                case 0x1EBE:
                case 0x1EC0:
                case 0x1EC2:
                case 0x1EC4:
                case 0x1EC6:
                case 0x1EC8:
                case 0x1ECA:
                case 0x1ECC:
                case 0x1ECE:
                case 0x1ED0:
                case 0x1ED2:
                case 0x1ED4:
                case 0x1ED6:
                case 0x1ED8:
                case 0x1EDA:
                case 0x1EDC:
                case 0x1EDE:
                case 0x1EE0:
                case 0x1EE2:
                case 0x1EE4:
                case 0x1EE6:
                case 0x1EE8:
                case 0x1EEA:
                case 0x1EEC:
                case 0x1EEE:
                case 0x1EF0:
                case 0x1EF2:
                case 0x1EF4:
                case 0x1EF6:
                case 0x1EF8:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1EA0-U+1EF8
                    target[limit++] = ( char ) ( c + 0x0001 );
                    break;
    
                case 0x1F08:
                case 0x1F09:
                case 0x1F0A:
                case 0x1F0B:
                case 0x1F0C:
                case 0x1F0D:
                case 0x1F0E:
                case 0x1F0F:
                case 0x1F18:
                case 0x1F19:
                case 0x1F1A:
                case 0x1F1B:
                case 0x1F1C:
                case 0x1F1D:
                case 0x1F28:
                case 0x1F29:
                case 0x1F2A:
                case 0x1F2B:
                case 0x1F2C:
                case 0x1F2D:
                case 0x1F2E:
                case 0x1F2F:
                case 0x1F38:
                case 0x1F39:
                case 0x1F3A:
                case 0x1F3B:
                case 0x1F3C:
                case 0x1F3D:
                case 0x1F3E:
                case 0x1F3F:
                case 0x1F48:
                case 0x1F49:
                case 0x1F4A:
                case 0x1F4B:
                case 0x1F4C:
                case 0x1F4D:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F08-U+1F4D
                    target[limit++] = ( char ) ( c - 0x0008 );
                    break;
    
                case 0x1F50:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F50
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0313;
                    break;
    
                case 0x1F52:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F52
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0313;
                    target[limit++] = 0x0300;
                    break;
    
                case 0x1F54:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F54
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0313;
                    target[limit++] = 0x0301;
                    break;
    
                case 0x1F56:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F56
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0313;
                    target[limit++] = 0x0342;
                    break;
    
                case 0x1F59:
                case 0x1F5B:
                case 0x1F5D:
                case 0x1F5F:
                case 0x1F68:
                case 0x1F69:
                case 0x1F6A:
                case 0x1F6B:
                case 0x1F6C:
                case 0x1F6D:
                case 0x1F6E:
                case 0x1F6F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F59-U+1F6F
                    target[limit++] = ( char ) ( c - 0x0008 );
                    break;
    
                case 0x1F80:
                case 0x1F81:
                case 0x1F82:
                case 0x1F83:
                case 0x1F84:
                case 0x1F85:
                case 0x1F86:
                case 0x1F87:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F80-U+1F87
                    target[limit++] = ( char ) ( c - 0x0080 );
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1F88:
                case 0x1F89:
                case 0x1F8A:
                case 0x1F8B:
                case 0x1F8C:
                case 0x1F8D:
                case 0x1F8E:
                case 0x1F8F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F88-U+1F8F
                    target[limit++] = ( char ) ( c - 0x0088 );
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1F90:
                case 0x1F91:
                case 0x1F92:
                case 0x1F93:
                case 0x1F94:
                case 0x1F95:
                case 0x1F96:
                case 0x1F97:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F90-U+1F97
                    target[limit++] = ( char ) ( c - 0x0070 );
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1F98:
                case 0x1F99:
                case 0x1F9A:
                case 0x1F9B:
                case 0x1F9C:
                case 0x1F9D:
                case 0x1F9E:
                case 0x1F9F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1F98-U+1F9F
                    target[limit++] = ( char ) ( c - 0x0078 );
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FA0:
                case 0x1FA1:
                case 0x1FA2:
                case 0x1FA3:
                case 0x1FA4:
                case 0x1FA5:
                case 0x1FA6:
                case 0x1FA7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FA0-U+1FA7
                    target[limit++] = ( char ) ( c - 0x0040 );
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FA8:
                case 0x1FA9:
                case 0x1FAA:
                case 0x1FAB:
                case 0x1FAC:
                case 0x1FAD:
                case 0x1FAE:
                case 0x1FAF:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FA8-U+1FAF
                    target[limit++] = ( char ) ( c - 0x0048 );
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FB2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FB2
                    target[limit++] = 0x1F70;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FB3:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FB3
                    target[limit++] = 0x03B1;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FB4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FB4
                    target[limit++] = 0x03AC;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FB6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FB6
                    target[limit++] = 0x03B1;
                    target[limit++] = 0x0342;
                    break;
    
                case 0x1FB7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FB7
                    target[limit++] = 0x03B1;
                    target[limit++] = 0x0342;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FB8:
                case 0x1FB9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FB8,U+1FB9
                    target[limit++] = ( char ) ( c - 0x0008 );
                    break;
    
                case 0x1FBA:
                case 0x1FBB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FBA,U+1FBB
                    target[limit++] = ( char ) ( c - 0x004A );
                    target[limit++] = 0x1F70;
                    break;
    
                case 0x1FBC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FBC
                    target[limit++] = 0x03B1;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FBE:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FBE
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FC2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FC2
                    target[limit++] = 0x1F74;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FC3:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FC3
                    target[limit++] = 0x03B7;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FC4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FC4
                    target[limit++] = 0x03AE;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FC6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FC6
                    target[limit++] = 0x03B7;
                    target[limit++] = 0x0342;
                    break;
    
                case 0x1FC7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FC7
                    target[limit++] = 0x03B7;
                    target[limit++] = 0x0342;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FC8:
                case 0x1FC9:
                case 0x1FCA:
                case 0x1FCB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FC8-U+01FCB
                    target[limit++] = ( char ) ( c - 0x0056 );
                    target[limit++] = 0x1F72;
                    break;
    
                case 0x1FCC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FCC
                    target[limit++] = 0x03B7;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FD2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FD2
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0300;
                    break;
    
                case 0x1FD3:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FD3
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0301;
                    break;
    
                case 0x1FD6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FD6
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0342;
                    break;
    
                case 0x1FD7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FD7
                    target[limit++] = 0x03B9;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0342;
                    break;
    
                case 0x1FD8:
                case 0x1FD9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FD8-U+01FD9
                    target[limit++] = ( char ) ( c - 0x0008 );
                    break;
    
                case 0x1FDA:
                case 0x1FDB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FD8-U+01FD9
                    target[limit++] = ( char ) ( c - 0x0064 );
                    break;
    
                case 0x1FE2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FE2
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0300;
                    break;
    
                case 0x1FE3:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FE3
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0301;
                    break;
    
                case 0x1FE4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FE4
                    target[limit++] = 0x03C1;
                    target[limit++] = 0x0313;
                    break;
    
                case 0x1FE6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FE6
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0342;
                    break;
    
                case 0x1FE7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FE7
                    target[limit++] = 0x03C5;
                    target[limit++] = 0x0308;
                    target[limit++] = 0x0342;
                    break;
    
                case 0x1FE8:
                case 0x1FE9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FE8-U+01FE9
                    target[limit++] = ( char ) ( c - 0x0008 );
                    break;
    
                case 0x1FEA:
                case 0x1FEB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FEA-U+01FEB
                    target[limit++] = ( char ) ( c - 0x0070 );
                    break;
    
                case 0x1FEC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FEC
                    target[limit++] = 0x1FE5;
                    break;
    
                case 0x1FF2:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FF2
                    target[limit++] = 0x1F7C;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FF3:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FF3
                    target[limit++] = 0x03C9;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FF4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FF4
                    target[limit++] = 0x03CE;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FF6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FF6
                    target[limit++] = 0x03C9;
                    target[limit++] = 0x0342;
                    break;
    
                case 0x1FF7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FF7
                    target[limit++] = 0x03C9;
                    target[limit++] = 0x0342;
                    target[limit++] = 0x03B9;
                    break;
    
                case 0x1FF8:
                case 0x1FF9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FF8-U+01FF9
                    target[limit++] = ( char ) ( c - 0x0080 );
                    break;
    
                case 0x1FFA:
                case 0x1FFB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FFA-U+01FFB
                    target[limit++] = ( char ) ( c - 0x007E );
                    target[limit++] = 0x1F7C;
                    break;
    
                case 0x1FFC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+1FFC
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
                    // All other code points with Separator (space, line, or paragraph) property 
                    // (e.g., Zs, Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
                    //  list of these code points: ...2000-200A...
                    target[limit++] = 0x0020;
                    break;
    
                case 0x200B:
                    // ZERO WIDTH SPACE (U+200B) is mapped to nothing.
                        break;
                    
                case 0x200C:
                case 0x200D:
                case 0x200E:
                case 0x200F:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+200C-200FF...
                    break;
    
                case 0x2028:
                case 0x2029:
                    // All other code points with Separator (space, line, or paragraph) property 
                    // (e.g., Zs, Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
                    //  list of these code points: ... 2028-2029...
                    target[limit++] = 0x0020;
                    break;
    
                case 0x202A:
                case 0x202B:
                case 0x202C:
                case 0x202D:
                case 0x202E:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+202A-202E...
                    break;
    
                case 0x202F:
                    // All other code points with Separator (space, line, or paragraph) property 
                    // (e.g., Zs, Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
                    //  list of these code points: ... 202F ...
                    target[limit++] = 0x0020;
                    break;
    
                case 0x205F:
                    // All other code points with Separator (space, line, or paragraph) property 
                    // (e.g., Zs, Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
                    //  list of these code points:...205F...
                    target[limit++] = 0x0020;
                    break;
    
                case 0x2060:
                case 0x2061:
                case 0x2062:
                case 0x2063:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+2060-2063...
                    break;
    
                case 0x206A:
                case 0x206B:
                case 0x206C:
                case 0x206D:
                case 0x206E:
                case 0x206F:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+20GA-20GFF...
                    break;
    
                case 0x20A8:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+20A8
                    target[limit++] = 0x0072;
                    target[limit++] = 0x0073;
                    break;
    
                case 0x2102:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2102
                    target[limit++] = 0x0063;
                    break;
    
                case 0x2103:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2103
                    target[limit++] = 0x00B0;
                    target[limit++] = 0x0063;
                    break;
    
                case 0x2107:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2107
                    target[limit++] = 0x025B;
                    break;
    
                case 0x2109:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2109
                    target[limit++] = 0x00B0;
                    target[limit++] = 0x0066;
                    break;
    
                case 0x210B:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+210B
                    target[limit++] = 0x0068;
                    break;
    
                case 0x210C:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+210C
                    target[limit++] = 0x0068;
                    break;
    
                case 0x210D:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+210D
                    target[limit++] = 0x0068;
                    break;
    
                case 0x2110:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2110
                    target[limit++] = 0x0069;
                    break;
    
                case 0x2111:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2111
                    target[limit++] = 0x0069;
                    break;
    
                case 0x2112:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2112
                    target[limit++] = 0x006C;
                    break;
    
                case 0x2115:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2115
                    target[limit++] = 0x006E;
                    break;
    
                case 0x2116:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2116
                    target[limit++] = 0x006E;
                    target[limit++] = 0x006F;
                    break;
    
                case 0x2119:
                case 0x211A:
                case 0x211B:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2119-U+211B
                    target[limit++] = ( char ) ( c - 0x2A09 );
                    break;
    
                case 0x211C:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+211C
                    target[limit++] = 0x0072;
                    break;
    
                case 0x211D:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+211D
                    target[limit++] = 0x0072;
                    break;
    
                case 0x2120:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2120
                    target[limit++] = 0x0073;
                    target[limit++] = 0x006D;
                    break;
    
                case 0x2121:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2121
                    target[limit++] = 0x0074;
                    target[limit++] = 0x0065;
                    target[limit++] = 0x006C;
                    break;
    
                case 0x2122:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2122
                    target[limit++] = 0x0074;
                    target[limit++] = 0x006D;
                    break;
    
                case 0x2124:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2122
                    target[limit++] = 0x007A;
                    break;
    
                case 0x2126:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2122
                    target[limit++] = 0x03C9;
                    break;
    
                case 0x2128:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2122
                    target[limit++] = 0x007A;
                    break;
    
                case 0x212A:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2122
                    target[limit++] = 0x006B;
                    break;
    
                case 0x212B:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2122
                    target[limit++] = 0x00E5;
                    break;
    
                case 0x212C:
                case 0x212D:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+212C-U+212D
                    target[limit++] = ( char ) ( c - 0x20CA );
                    break;
    
                case 0x2130:
                case 0x2131:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2130-U+2131
                    target[limit++] = ( char ) ( c - 0x20CB );
                    break;
    
                case 0x2133:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2133
                    target[limit++] = 0x006D;
                    break;
    
                case 0x213E:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+213E
                    target[limit++] = 0x03B3;
                    break;
    
                case 0x213F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+213F
                    target[limit++] = 0x03C0;
                    break;
    
                case 0x2145:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2145
                    target[limit++] = 0x0064;
                    break;
    
                case 0x2160:
                case 0x2161:
                case 0x2162:
                case 0x2163:
                case 0x2164:
                case 0x2165:
                case 0x2166:
                case 0x2167:
                case 0x2168:
                case 0x2169:
                case 0x216A:
                case 0x216B:
                case 0x216C:
                case 0x216D:
                case 0x216E:
                case 0x216F:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+2160-U+216F
                    target[limit++] = ( char ) ( c + 0x0010 );
                    break;
    
                case 0x24B6:
                case 0x24B7:
                case 0x24B8:
                case 0x24B9:
                case 0x24BA:
                case 0x24BB:
                case 0x24BC:
                case 0x24BD:
                case 0x24BE:
                case 0x24BF:
                case 0x24C0:
                case 0x24C1:
                case 0x24C2:
                case 0x24C3:
                case 0x24C4:
                case 0x24C5:
                case 0x24C6:
                case 0x24C7:
                case 0x24C8:
                case 0x24C9:
                case 0x24CA:
                case 0x24CB:
                case 0x24CC:
                case 0x24CD:
                case 0x24CE:
                case 0x24CF:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+24B6-U+24CF
                    target[limit++] = ( char ) ( c + 0x001A );
                    break;
    
                case 0x3000:
                    // All other code points with Separator (space, line, or paragraph) property 
                    // (e.g., Zs, Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
                    //  list of these code points: ...3000.
                    target[limit++] = 0x0020;
                    break;
    
                case 0x3371:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3371
                    target[limit++] = 0x0068;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;
    
                case 0x3373:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3373
                    target[limit++] = 0x0061;
                    target[limit++] = 0x0075;
                    break;
    
                case 0x3375:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3375
                    target[limit++] = 0x006F;
                    target[limit++] = 0x0076;
                    break;
    
                case 0x3380:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3380
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;
    
                case 0x3381:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3381
                    target[limit++] = 0x006E;
                    target[limit++] = 0x0061;
                    break;
    
                case 0x3382:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3382
                    target[limit++] = 0x03BC;
                    target[limit++] = 0x0061;
                    break;
    
                case 0x3383:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3383
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0061;
                    break;
    
                case 0x3384:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3384
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0061;
                    break;
    
                case 0x3385:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3385
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0062;
                    break;
    
                case 0x3386:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3386
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0062;
                    break;
    
                case 0x3387:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3387
                    target[limit++] = 0x0067;
                    target[limit++] = 0x0062;
                    break;
    
                case 0x338A:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+338A
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0066;
                    break;
    
                case 0x338B:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+338B
                    target[limit++] = 0x006E;
                    target[limit++] = 0x0066;
                    break;
    
                case 0x338C:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+338C
                    target[limit++] = 0x03BC;
                    target[limit++] = 0x0066;
                    break;
    
                case 0x3390:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3390
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;
    
                case 0x3391:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3391
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;
    
                case 0x3392:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3392
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;
    
                case 0x3393:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3393
                    target[limit++] = 0x0067;
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;
    
                case 0x3394:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+3394
                    target[limit++] = 0x0074;
                    target[limit++] = 0x0068;
                    target[limit++] = 0x007A;
                    break;
    
                case 0x33A9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33A9
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;
    
                case 0x33AA:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33AA
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;
    
                case 0x33AB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33AB
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;
    
                case 0x33AC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33AC
                    target[limit++] = 0x0067;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0061;
                    break;
    
                case 0x33B4:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33B4
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0076;
                    break;
    
                case 0x33B5:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33B5
                    target[limit++] = 0x006E;
                    target[limit++] = 0x0076;
                    break;
    
                case 0x33B6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33B6
                    target[limit++] = 0x03BC;
                    target[limit++] = 0x0076;
                    break;
    
                case 0x33B7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33B7
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0076;
                    break;
    
                case 0x33B8:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33B8
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0076;
                    break;
    
                case 0x33B9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33B9
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0076;
                    break;
    
                case 0x33BA:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33BA
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0077;
                    break;
    
                case 0x33BB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33BB
                    target[limit++] = 0x006E;
                    target[limit++] = 0x0077;
                    break;
    
                case 0x33BC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33BC
                    target[limit++] = 0x03BC;
                    target[limit++] = 0x0077;
                    break;
    
                case 0x33BD:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33BD
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0077;
                    break;
    
                case 0x33BE:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33BE
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0077;
                    break;
    
                case 0x33BF:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33BF
                    target[limit++] = 0x006D;
                    target[limit++] = 0x0077;
                    break;
    
                case 0x33C0:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33C0
                    target[limit++] = 0x006B;
                    target[limit++] = 0x03C9;
                    break;
    
                case 0x33C1:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33C1
                    target[limit++] = 0x006D;
                    target[limit++] = 0x03C9;
                    break;
    
                case 0x33C3:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33C3
                    target[limit++] = 0x0062;
                    target[limit++] = 0x0071;
                    break;
    
                case 0x33C6:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33C6
                    target[limit++] = 0x0063;
                    target[limit++] = 0x2215;
                    target[limit++] = 0x006B;
                    target[limit++] = 0x0067;
                    break;
    
                case 0x33C7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33C7
                    target[limit++] = 0x0063;
                    target[limit++] = 0x006F;
                    target[limit++] = 0x002E;
                    break;
    
                case 0x33C8:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33C8
                    target[limit++] = 0x0064;
                    target[limit++] = 0x0062;
                    break;
    
                case 0x33C9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33C9
                    target[limit++] = 0x0067;
                    target[limit++] = 0x0079;
                    break;
    
                case 0x33CB:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33CB
                    target[limit++] = 0x0068;
                    target[limit++] = 0x0070;
                    break;
    
                case 0x33CD:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33CD
                    target[limit++] = 0x006B;
                    target[limit++] = 0x006B;
                    break;
    
                case 0x33CE:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33CE
                    target[limit++] = 0x006B;
                    target[limit++] = 0x006D;
                    break;
    
                case 0x33D7:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33D7
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0068;
                    break;
    
                case 0x33D9:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33D9
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0070;
                    target[limit++] = 0x006D;
                    break;
    
                case 0x33DA:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33DA
                    target[limit++] = 0x0070;
                    target[limit++] = 0x0072;
                    break;
    
                case 0x33DC:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33DC
                    target[limit++] = 0x0073;
                    target[limit++] = 0x0076;
                    break;
    
                case 0x33DD:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+33DD
                    target[limit++] = 0x0077;
                    target[limit++] = 0x0062;
                    break;
    
                case 0xFB00:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB00
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0066;
                    break;
    
                case 0xFB01:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB01
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0069;
                    break;
    
                case 0xFB02:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB02
                    target[limit++] = 0x0066;
                    target[limit++] = 0x006C;
                    break;
    
                case 0xFB03:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB03
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0069;
                    break;
    
                case 0xFB04:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB04
                    target[limit++] = 0x0066;
                    target[limit++] = 0x0066;
                    target[limit++] = 0x006C;
                    break;
    
                case 0xFB05:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB05
                    target[limit++] = 0x0073;
                    target[limit++] = 0x0074;
                    break;
    
                case 0xFB06:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB06
                    target[limit++] = 0x0073;
                    target[limit++] = 0x0074;
                    break;
    
                case 0xFB13:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB13
                    target[limit++] = 0x0574;
                    target[limit++] = 0x0576;
                    break;
    
                case 0xFB14:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB14
                    target[limit++] = 0x0574;
                    target[limit++] = 0x0565;
                    break;
    
                case 0xFB15:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB15
                    target[limit++] = 0x0574;
                    target[limit++] = 0x056B;
                    break;
    
                case 0xFB16:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB16
                    target[limit++] = 0x057E;
                    target[limit++] = 0x0576;
                    break;
    
                case 0xFB17:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FB17
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
                    // SOFT HYPHEN (U+00AD) and MONGOLIAN TODO SOFT HYPHEN (U+1806) code
                    // points are mapped to nothing.  COMBINING GRAPHEME JOINER (U+034F) and
                    // VARIATION SELECTORs (U+180B-180D, FE00-FE0F) code points are also
                    // mapped to nothing.  The OBJECT REPLACEMENT CHARACTER (U+FFFC) is
                    // mapped to nothing.
                    break;
    
                case 0xFEFF:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+FEFF...
                    break;
    
                case 0xFF21:
                case 0xFF22:
                case 0xFF23:
                case 0xFF24:
                case 0xFF25:
                case 0xFF26:
                case 0xFF27:
                case 0xFF28:
                case 0xFF29:
                case 0xFF2A:
                case 0xFF2B:
                case 0xFF2C:
                case 0xFF2D:
                case 0xFF2E:
                case 0xFF2F:
                case 0xFF30:
                case 0xFF31:
                case 0xFF32:
                case 0xFF33:
                case 0xFF34:
                case 0xFF35:
                case 0xFF36:
                case 0xFF37:
                case 0xFF38:
                case 0xFF39:
                case 0xFF3A:
                    // For case ignore, numeric, and stored prefix string matching rules,
                    // characters are case folded per B.2 of [RFC3454] : U+FF21-FF3A
                    target[limit++] = ( char ) ( c + 0x0020 );
                    break;
    
                case 0xFFF9:
                case 0xFFFA:
                case 0xFFFB:
                    // All other control code (e.g., Cc) points or code points with a
                    // control function (e.g., Cf) are mapped to nothing.  The following is
                    // a complete list of these code points: ... U+FFF9-FFFB...
                    break;
                    
                case 0xFFFC:
                    // SOFT HYPHEN (U+00AD) and MONGOLIAN TODO SOFT HYPHEN (U+1806) code
                    // points are mapped to nothing.  COMBINING GRAPHEME JOINER (U+034F) and
                    // VARIATION SELECTORs (U+180B-180D, FF00-FE0F) code points are also
                    // mapped to nothing.  The OBJECT REPLACEMENT CHARACTER (U+FFFC) is
                    // mapped to nothing.
                    break;
    
                default:
                    // First, eliminate surrogates, and replace them by FFFD char
                    if ( ( c >= 0xD800 ) && ( c <= 0xDFFF ) )
                    {
                        target[limit++] = 0xFFFD;
                        break;
                    }
    
                    target[limit++] = c;
                    break;
            }
        }
    
        return new String( target, 0, limit );
    }
}
