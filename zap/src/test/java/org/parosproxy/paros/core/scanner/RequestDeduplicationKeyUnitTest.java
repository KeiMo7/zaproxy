/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.parosproxy.paros.core.scanner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

/** Unit test for {@link RequestDeduplicationKey}. */
class RequestDeduplicationKeyUnitTest {

    @Test
    void shouldIgnoreQueryParameterOrder() throws Exception {
        // Given
        HttpMessage first = message("GET", "/search?b=2&a=1");
        HttpMessage second = message("GET", "/search?a=1&b=2");
        // When
        RequestDeduplicationKey key1 =
                RequestDeduplicationKey.from(first, RequestDeduplicationMode.AUTO);
        RequestDeduplicationKey key2 =
                RequestDeduplicationKey.from(second, RequestDeduplicationMode.AUTO);
        // Then
        assertThat(key1.getParameterNames(), is(equalTo(key2.getParameterNames())));
        assertThat(key1.getRequestFingerprint(), is(equalTo(key2.getRequestFingerprint())));
        assertThat(
                key1.getAuthenticationFingerprint(),
                is(equalTo(key2.getAuthenticationFingerprint())));
        assertThat(key1, is(equalTo(key2)));
    }

    @Test
    void shouldNotShareDifferentQueryParameterValues() throws Exception {
        // Given
        HttpMessage first = message("GET", "/search?q=test");
        HttpMessage second = message("GET", "/search?q=test%27");
        // When
        RequestDeduplicationKey key1 =
                RequestDeduplicationKey.from(first, RequestDeduplicationMode.AUTO);
        RequestDeduplicationKey key2 =
                RequestDeduplicationKey.from(second, RequestDeduplicationMode.AUTO);
        // Then
        assertThat(key1, is(not(equalTo(key2))));
    }

    @Test
    void shouldNotShareDifferentParameterNames() throws Exception {
        // Given
        HttpMessage first = message("GET", "/search?a=1");
        HttpMessage second = message("GET", "/search?b=1");
        // When
        RequestDeduplicationKey key1 =
                RequestDeduplicationKey.from(first, RequestDeduplicationMode.AUTO);
        RequestDeduplicationKey key2 =
                RequestDeduplicationKey.from(second, RequestDeduplicationMode.AUTO);
        // Then
        assertThat(key1, is(not(equalTo(key2))));
    }

    @Test
    void shouldNotShareDifferentPayloads() throws Exception {
        // Given
        HttpMessage first = message("POST", "/login", "application/x-www-form-urlencoded", "u=a");
        HttpMessage second =
                message("POST", "/login", "application/x-www-form-urlencoded", "u=a%27");
        // When
        RequestDeduplicationKey key1 =
                RequestDeduplicationKey.from(first, RequestDeduplicationMode.AUTO);
        RequestDeduplicationKey key2 =
                RequestDeduplicationKey.from(second, RequestDeduplicationMode.AUTO);
        // Then
        assertThat(key1, is(not(equalTo(key2))));
    }

    @Test
    void shouldKeepDifferentSessionCookiesSeparateInAutoMode() throws Exception {
        // Given
        HttpMessage first = messageWithHeader("GET", "/account", "Cookie: session=one");
        HttpMessage second = messageWithHeader("GET", "/account", "Cookie: session=two");
        // When
        RequestDeduplicationKey key1 =
                RequestDeduplicationKey.from(first, RequestDeduplicationMode.AUTO);
        RequestDeduplicationKey key2 =
                RequestDeduplicationKey.from(second, RequestDeduplicationMode.AUTO);
        // Then
        assertThat(key1, is(not(equalTo(key2))));
        assertThat(key1.isAuthenticationPresent(), is(equalTo(true)));
    }

    @Test
    void shouldShareAcrossCookiesInStatelessMode() throws Exception {
        // Given
        HttpMessage first = messageWithHeader("GET", "/account", "Cookie: session=one");
        HttpMessage second = messageWithHeader("GET", "/account", "Cookie: session=two");
        // When
        RequestDeduplicationKey key1 =
                RequestDeduplicationKey.from(first, RequestDeduplicationMode.STATELESS);
        RequestDeduplicationKey key2 =
                RequestDeduplicationKey.from(second, RequestDeduplicationMode.STATELESS);
        // Then
        assertThat(key1, is(equalTo(key2)));
        assertThat(key1.isAuthenticationPresent(), is(equalTo(true)));
    }

    @Test
    void shouldNotShareAuthenticatedAndAnonymousRequestsInStatelessMode() throws Exception {
        // Given
        HttpMessage authenticated = messageWithHeader("GET", "/account", "Cookie: session=one");
        HttpMessage anonymous = message("GET", "/account");
        // When
        RequestDeduplicationKey key1 =
                RequestDeduplicationKey.from(authenticated, RequestDeduplicationMode.STATELESS);
        RequestDeduplicationKey key2 =
                RequestDeduplicationKey.from(anonymous, RequestDeduplicationMode.STATELESS);
        // Then
        assertThat(key1, is(not(equalTo(key2))));
    }

    @Test
    void shouldKeepVariantNamespacesSeparate() throws Exception {
        // Given
        HttpMessage message = message("POST", "/search", "application/json", "{\"q\":\"test\"}");
        // When
        RequestDeduplicationKey key1 =
                RequestDeduplicationKey.from(message, RequestDeduplicationMode.AUTO, "plugin-a");
        RequestDeduplicationKey key2 =
                RequestDeduplicationKey.from(message, RequestDeduplicationMode.AUTO, "plugin-b");
        // Then
        assertThat(key1, is(not(equalTo(key2))));
    }

    @Test
    void endpointSignatureShouldIgnoreParameterValues() throws Exception {
        // Given
        HttpMessage first = message("GET", "/search?q=one");
        HttpMessage second = message("GET", "/search?q=two");
        // When / Then
        assertThat(
                RequestDeduplicationKey.endpointSignature(first),
                is(equalTo(RequestDeduplicationKey.endpointSignature(second))));
    }

    @Test
    void shouldRoundTripSerialisedKey() throws Exception {
        // Given
        RequestDeduplicationKey key =
                RequestDeduplicationKey.from(
                        message("GET", "/search?q=test"),
                        RequestDeduplicationMode.AUTO,
                        "plugin\nvariant");
        // When
        RequestDeduplicationKey restored = RequestDeduplicationKey.deserialise(key.serialise());
        // Then
        assertThat(restored, is(equalTo(key)));
    }

    private static HttpMessage message(String method, String path) throws Exception {
        return messageWithHeader(method, path);
    }

    private static HttpMessage message(String method, String path, String contentType, String body)
            throws Exception {
        HttpMessage message =
                messageWithHeader(
                        method, path, "Content-Type: " + contentType + "\r\nContent-Length: 0");
        message.setRequestBody(body);
        return message;
    }

    private static HttpMessage messageWithHeader(String method, String path, String... extraHeaders)
            throws Exception {
        StringBuilder header = new StringBuilder();
        header.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
        header.append("Host: example.com\r\n");
        for (String extraHeader : extraHeaders) {
            header.append(extraHeader).append("\r\n");
        }
        header.append("\r\n");
        return new HttpMessage(new HttpRequestHeader(header.toString()));
    }
}
