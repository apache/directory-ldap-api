package org.apache.directory.api.ldap.model.message.controls;

import org.junit.jupiter.api.Test;

import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
//import org.apache.directory.api.ldap.model.message.controls.PagedResultsImpl;
//import org.apache.directory.server.ldap.handlers.controls.PagedSearchContext;
//import org.junit.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests illustrating that PagedResultsImpl cookie decoding does not match PagedSearchContext cookie encoding for
 * at least one range of message ids.
 */
public class PagedSearchCookieTest {

    @Test
    public void testCookieCalculationGoodUpper() {
        SearchRequest searchRequest = new SearchRequestImpl();
        searchRequest.setMessageId(65536);
        int cookieValue = 65536;

        byte[] cookie = BerValue.getBytes(cookieValue);

        PagedResultsImpl pagedResults = new PagedResultsImpl();
        pagedResults.setCookie(cookie);

        int uncookieValue = pagedResults.getCookieValue();
        assertEquals(cookieValue, uncookieValue); // succeeds
    }

    @Test
    public void testCookieCalculationBadUpperLimit() {
        int cookieValue = 65535;

        byte[] cookie = BerValue.getBytes(cookieValue);

        PagedResultsImpl pagedResults = new PagedResultsImpl();
        pagedResults.setCookie(cookie);

        int uncookieValue = pagedResults.getCookieValue();
        assertEquals(cookieValue, uncookieValue); // fails
    }

    @Test
    public void testCookieCalculationBadLowerLimit() {
        int cookieValue = ((65408<<16) & 0x7FFFFFFF);

        byte[] cookie = BerValue.getBytes(cookieValue);

        PagedResultsImpl pagedResults = new PagedResultsImpl();
        pagedResults.setCookie(cookie);

        int uncookieValue = pagedResults.getCookieValue();
        assertEquals(cookieValue, uncookieValue); // fails
    }

    @Test
    public void testCookieCalculationGoodLower() {
        int cookieValue = 65407;

        byte[] cookie = BerValue.getBytes(cookieValue);

        PagedResultsImpl pagedResults = new PagedResultsImpl();
        pagedResults.setCookie(cookie);

        int uncookieValue = pagedResults.getCookieValue();
        assertEquals(cookieValue, uncookieValue); // succeeds
    }
}