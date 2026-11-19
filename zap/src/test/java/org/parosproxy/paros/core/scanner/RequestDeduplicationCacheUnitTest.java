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
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

/** Unit test for {@link RequestDeduplicationCache}. */
class RequestDeduplicationCacheUnitTest {

    private static final String RESPONSE_HEADER =
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n";

    @Test
    void shouldSendIdenticalRequestOnlyOnce() throws Exception {
        // Given
        RequestDeduplicationCache cache = cache(10, 1024 * 1024, 60_000);
        RequestDeduplicationKey key = key("/search?q=test");
        AtomicInteger sends = new AtomicInteger();
        RequestDeduplicationCache.RequestSender sender = () -> response(sends, "ok");
        // When
        CachedHttpResponse first = cache.getOrSend(key, sender);
        CachedHttpResponse second = cache.getOrSend(key, sender);
        // Then
        assertThat(sends.get(), is(equalTo(1)));
        assertThat(first.getBody(), is(equalTo(second.getBody())));
        assertThat(cache.getStats().getHits(), is(equalTo(1L)));
        assertThat(cache.getStats().getMisses(), is(equalTo(1L)));
        assertThat(cache.getStats().getHitRate(), is(equalTo(0.5)));
    }

    @Test
    void shouldCoalesceConcurrentRequests() throws Exception {
        // Given
        RequestDeduplicationCache cache = cache(10, 1024 * 1024, 60_000);
        RequestDeduplicationKey key = key("/search?q=test");
        AtomicInteger sends = new AtomicInteger();
        CountDownLatch senderEntered = new CountDownLatch(1);
        CountDownLatch releaseSender = new CountDownLatch(1);
        RequestDeduplicationCache.RequestSender sender =
                () -> {
                    senderEntered.countDown();
                    try {
                        releaseSender.await(5, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new java.io.IOException(e);
                    }
                    return response(sends, "ok");
                };
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            // When
            Future<CachedHttpResponse> first = executor.submit(() -> cache.getOrSend(key, sender));
            assertThat(senderEntered.await(5, TimeUnit.SECONDS), is(equalTo(true)));
            Future<CachedHttpResponse> second = executor.submit(() -> cache.getOrSend(key, sender));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (cache.getStats().getRequests() < 2 && System.nanoTime() < deadline) {
                Thread.sleep(1);
            }
            assertThat(cache.getStats().getRequests(), is(equalTo(2L)));
            releaseSender.countDown();

            // Then
            assertThat(first.get(5, TimeUnit.SECONDS).getBody().length, is(equalTo(2)));
            assertThat(second.get(5, TimeUnit.SECONDS).getBody().length, is(equalTo(2)));
            assertThat(sends.get(), is(equalTo(1)));
            assertThat(cache.getStats().getCoalescedHits(), is(equalTo(1L)));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void shouldResendExpiredResponse() throws Exception {
        // Given
        RequestDeduplicationCache cache = cache(10, 1024 * 1024, 1);
        RequestDeduplicationKey key = key("/search?q=test");
        AtomicInteger sends = new AtomicInteger();
        cache.getOrSend(key, () -> response(sends, "ok"));
        Thread.sleep(10);
        // When
        cache.getOrSend(key, () -> response(sends, "ok"));
        // Then
        assertThat(sends.get(), is(equalTo(2)));
        assertThat(cache.getStats().getExpired(), is(equalTo(1L)));
    }

    @Test
    void shouldEvictLeastRecentlyUsedEntry() throws Exception {
        // Given
        RequestDeduplicationCache cache = cache(1, 1024 * 1024, 60_000);
        RequestDeduplicationKey first = key("/first");
        RequestDeduplicationKey second = key("/second");
        AtomicInteger sends = new AtomicInteger();
        cache.getOrSend(first, () -> response(sends, "one"));
        cache.getOrSend(second, () -> response(sends, "two"));
        // When
        cache.getOrSend(first, () -> response(sends, "one"));
        // Then
        assertThat(sends.get(), is(equalTo(3)));
        assertThat(cache.size(), is(equalTo(1)));
        assertThat(cache.getStats().getEvicted(), is(greaterThan(0L)));
    }

    @Test
    void shouldInvalidateSharedResponsesAfterSideEffect() throws Exception {
        // Given
        RequestDeduplicationCache cache = cache(10, 1024 * 1024, 60_000);
        HttpMessage message = message("POST", "/users", "name=test");
        RequestDeduplicationKey key =
                RequestDeduplicationKey.from(message, RequestDeduplicationMode.AUTO);
        AtomicInteger sends = new AtomicInteger();
        cache.getOrSend(key, () -> response(sends, "created"));
        // When
        cache.recordSideEffect(message, RequestDeduplicationMode.AUTO);
        cache.getOrSend(key, () -> response(sends, "created"));
        // Then
        assertThat(sends.get(), is(equalTo(2)));
        assertThat(cache.getStats().getSideEffectInvalidations(), is(equalTo(1L)));
    }

    @Test
    void shouldPersistAndRestoreResponses(@TempDir Path tempDir) throws Exception {
        // Given
        Path file = tempDir.resolve("cache.bin");
        RequestDeduplicationCache cache = cache(10, 1024 * 1024, 60_000);
        RequestDeduplicationKey key = key("/search?q=test");
        AtomicInteger sends = new AtomicInteger();
        cache.getOrSend(key, () -> response(sends, "ok"));
        cache.updateStructure("http://example.com:80", Set.of("GET /search q"));
        cache.save(file);
        RequestDeduplicationCache restored = cache(10, 1024 * 1024, 60_000);
        // When
        restored.load(file);
        restored.getOrSend(key, () -> response(sends, "ok"));
        // Then
        assertThat(Files.isRegularFile(file), is(equalTo(true)));
        assertThat(sends.get(), is(equalTo(1)));
        assertThat(restored.getStats().getHits(), is(equalTo(1L)));
    }

    @Test
    void shouldDiscardPersistedResponsesWhenStructureChangesTooMuch(@TempDir Path tempDir)
            throws Exception {
        // Given
        Path file = tempDir.resolve("cache.bin");
        RequestDeduplicationCache cache = cache(10, 1024 * 1024, 60_000);
        RequestDeduplicationKey key = key("/search?q=test");
        AtomicInteger sends = new AtomicInteger();
        cache.getOrSend(key, () -> response(sends, "ok"));
        cache.updateStructure("http://example.com:80", Set.of("first"));
        cache.save(file);
        RequestDeduplicationCache restored = cache(10, 1024 * 1024, 60_000);
        restored.load(file);
        // When
        restored.updateStructure(
                "http://example.com:80", Set.of("second", "third", "fourth", "fifth"));
        restored.getOrSend(key, () -> response(sends, "ok"));
        // Then
        assertThat(sends.get(), is(equalTo(2)));
        assertThat(restored.getStats().getStructureInvalidations(), is(equalTo(1L)));
    }

    @Test
    void shouldBoundIndexMemory() throws Exception {
        // Given
        RequestDeduplicationCache cache = cache(100, 700, 60_000);
        AtomicInteger sends = new AtomicInteger();
        // When
        for (int i = 0; i < 20; i++) {
            RequestDeduplicationKey key = key("/search?q=" + i);
            cache.getOrSend(key, () -> response(sends, "a response body"));
        }
        // Then
        assertThat(cache.getEstimatedBytes() <= 700, is(equalTo(true)));
        assertThat(cache.size() < 20, is(equalTo(true)));
    }

    private static RequestDeduplicationCache cache(int maxEntries, long maxBytes, long ttlMillis) {
        return new RequestDeduplicationCache(
                new RequestDeduplicationCache.Config(maxEntries, maxBytes, ttlMillis, 0.25));
    }

    private static RequestDeduplicationKey key(String path) throws Exception {
        return RequestDeduplicationKey.from(
                message("GET", path, null), RequestDeduplicationMode.AUTO);
    }

    private static CachedHttpResponse response(AtomicInteger sends, String body) {
        sends.incrementAndGet();
        return new CachedHttpResponse(
                RESPONSE_HEADER, body.getBytes(java.nio.charset.StandardCharsets.UTF_8), 1, true);
    }

    private static HttpMessage message(String method, String path, String body) throws Exception {
        HttpMessage message =
                new HttpMessage(
                        new HttpRequestHeader(
                                method + " " + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n"));
        if (body != null) {
            message.setRequestBody(body);
        }
        return message;
    }
}
