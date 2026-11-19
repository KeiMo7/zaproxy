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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

/**
 * An immutable snapshot of an HTTP response that can be applied to another request message.
 *
 * @since 2.18.0
 */
public final class CachedHttpResponse {

    private final String header;
    private final byte[] body;
    private final int timeElapsedMillis;
    private final boolean responseFromTargetHost;

    /**
     * Creates a response snapshot.
     *
     * @param header the complete response header.
     * @param body the response body.
     * @param timeElapsedMillis the time taken by the original request.
     * @param responseFromTargetHost whether the original response came from the target host.
     */
    public CachedHttpResponse(
            String header, byte[] body, int timeElapsedMillis, boolean responseFromTargetHost) {
        this.header = header == null ? "" : header;
        this.body = body == null ? new byte[0] : Arrays.copyOf(body, body.length);
        this.timeElapsedMillis = timeElapsedMillis;
        this.responseFromTargetHost = responseFromTargetHost;
    }

    /**
     * Captures the response of the given message.
     *
     * @param message the message whose response should be captured.
     * @return the response snapshot.
     */
    public static CachedHttpResponse from(HttpMessage message) {
        return new CachedHttpResponse(
                message.getResponseHeader().toString(),
                message.getResponseBody().getBytes(),
                message.getTimeElapsedMillis(),
                message.isResponseFromTargetHost());
    }

    /**
     * Applies this response to the given message, leaving its request untouched.
     *
     * @param message the message to update.
     * @throws HttpMalformedHeaderException if the cached header is malformed.
     */
    public void applyTo(HttpMessage message) throws HttpMalformedHeaderException {
        message.getResponseHeader().setMessage(header);
        message.setResponseBody(body);
        message.setTimeElapsedMillis(timeElapsedMillis);
        message.setResponseFromTargetHost(responseFromTargetHost);
    }

    public String getHeader() {
        return header;
    }

    public byte[] getBody() {
        return Arrays.copyOf(body, body.length);
    }

    public int getTimeElapsedMillis() {
        return timeElapsedMillis;
    }

    public boolean isResponseFromTargetHost() {
        return responseFromTargetHost;
    }

    long estimatedSize() {
        return 64L + header.getBytes(StandardCharsets.UTF_8).length + body.length;
    }
}
