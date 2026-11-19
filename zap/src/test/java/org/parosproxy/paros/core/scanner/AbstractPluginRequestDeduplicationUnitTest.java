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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;

/** Unit test for request deduplication in {@link AbstractPlugin}. */
class AbstractPluginRequestDeduplicationUnitTest {

    private HostProcess parent;
    private ScannerParam scannerParam;
    private HttpSender sender;
    private RequestDeduplicationCache cache;
    private AtomicInteger networkRequests;
    private HttpMessage baseMessage;

    @BeforeEach
    void setUp() throws Exception {
        parent = mock(HostProcess.class);
        scannerParam = mock(ScannerParam.class);
        sender = mock(HttpSender.class);
        cache = new RequestDeduplicationCache(100, 1024 * 1024, 60_000);
        networkRequests = new AtomicInteger();

        given(parent.getScannerParam()).willReturn(scannerParam);
        given(parent.getHttpSender()).willReturn(sender);
        given(parent.getRequestDeduplicationCache()).willReturn(cache);
        given(parent.isRequestDeduplicationEnabled(any()))
                .willAnswer(
                        invocation ->
                                ((Plugin) invocation.getArgument(0))
                                        .isRequestDeduplicationEnabled());
        willAnswer(
                        invocation -> {
                            HttpMessage message = invocation.getArgument(0);
                            networkRequests.incrementAndGet();
                            message.setResponseHeader(
                                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n");
                            message.setResponseBody("ok");
                            return null;
                        })
                .given(sender)
                .sendAndReceive(any(HttpMessage.class), anyBoolean());

        baseMessage =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET /search?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n"));
    }

    @Test
    void shouldReuseResponseWithoutSkippingPluginLogic() throws Exception {
        // Given
        ProbingPlugin plugin = new ProbingPlugin();
        plugin.init(baseMessage, parent);
        // When
        boolean firstDetected = plugin.probe();
        boolean secondDetected = plugin.probe();
        // Then
        assertThat(firstDetected, is(equalTo(true)));
        assertThat(secondDetected, is(equalTo(true)));
        assertThat(plugin.getProbeCount(), is(equalTo(2)));
        assertThat(networkRequests.get(), is(equalTo(1)));
        assertThat(cache.getStats().getHits(), is(equalTo(1L)));
    }

    @Test
    void shouldRespectPluginDisabledDeduplication() throws Exception {
        // Given
        ProbingPlugin plugin = new ProbingPlugin();
        plugin.setRequestDeduplicationEnabled(false);
        plugin.init(baseMessage, parent);
        // When
        plugin.probe();
        plugin.probe();
        // Then
        assertThat(networkRequests.get(), is(equalTo(2)));
        assertThat(cache.getStats().getRequests(), is(equalTo(0L)));
    }

    private static final class ProbingPlugin extends AbstractPlugin {

        private int probeCount;

        private boolean probe() throws IOException {
            probeCount++;
            HttpMessage message = getNewMsg();
            sendAndReceive(message, false, false);
            return message.getResponseBody().toString().equals("ok");
        }

        private int getProbeCount() {
            return probeCount;
        }

        @Override
        public int getId() {
            return 1;
        }

        @Override
        public String getName() {
            return "Probing Plugin";
        }

        @Override
        public String getDescription() {
            return "";
        }

        @Override
        public int getRisk() {
            return 0;
        }

        @Override
        public void scan() {}

        @Override
        public int getCategory() {
            return 0;
        }

        @Override
        public String getSolution() {
            return "";
        }

        @Override
        public String getReference() {
            return "";
        }

        @Override
        public void notifyPluginCompleted(HostProcess parent) {}

        @Override
        public boolean isVisible() {
            return true;
        }
    }
}
