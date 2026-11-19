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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Thread-safe request response cache used by the active scanner.
 *
 * <p>The cache only stores responses; plugins are still run for every parameter and message, so
 * sharing a response cannot bypass a plugin's detection logic. Concurrent requests with the same
 * key are coalesced into a single send.
 *
 * @since 2.18.0
 */
public final class RequestDeduplicationCache {

    private static final Logger LOGGER = LogManager.getLogger(RequestDeduplicationCache.class);
    private static final int FILE_MAGIC = 0x5a415044;
    private static final int FILE_VERSION = 1;
    private static final int MAX_SERIALISED_STRING = 64 * 1024 * 1024;

    /** Sends a request and captures its response. */
    @FunctionalInterface
    public interface RequestSender {
        CachedHttpResponse send() throws IOException;
    }

    /** The result of a request deduplication lookup. */
    public static final class Result {

        private final CachedHttpResponse response;
        private final boolean sent;

        private Result(CachedHttpResponse response, boolean sent) {
            this.response = response;
            this.sent = sent;
        }

        public CachedHttpResponse getResponse() {
            return response;
        }

        /**
         * Tells whether the request was sent to the target.
         *
         * @return {@code true} if the request was sent, {@code false} if a shared response was
         *     used.
         */
        public boolean isSent() {
            return sent;
        }
    }

    /** Configuration for a request deduplication cache. */
    public static final class Config {

        private final int maxEntries;
        private final long maxBytes;
        private final long ttlMillis;
        private final double structureChangeThreshold;

        public Config(
                int maxEntries, long maxBytes, long ttlMillis, double structureChangeThreshold) {
            if (maxEntries <= 0) {
                throw new IllegalArgumentException("maxEntries must be greater than zero.");
            }
            if (maxBytes <= 0) {
                throw new IllegalArgumentException("maxBytes must be greater than zero.");
            }
            if (ttlMillis <= 0) {
                throw new IllegalArgumentException("ttlMillis must be greater than zero.");
            }
            if (structureChangeThreshold < 0 || structureChangeThreshold > 1) {
                throw new IllegalArgumentException(
                        "structureChangeThreshold must be between 0 and 1.");
            }
            this.maxEntries = maxEntries;
            this.maxBytes = maxBytes;
            this.ttlMillis = ttlMillis;
            this.structureChangeThreshold = structureChangeThreshold;
        }

        public int getMaxEntries() {
            return maxEntries;
        }

        public long getMaxBytes() {
            return maxBytes;
        }

        public long getTtlMillis() {
            return ttlMillis;
        }

        public double getStructureChangeThreshold() {
            return structureChangeThreshold;
        }
    }

    private static final class Entry {
        private final CachedHttpResponse response;
        private final long expiresAtMillis;
        private final long generation;
        private final long estimatedSize;

        private Entry(
                CachedHttpResponse response, long expiresAtMillis, long generation, long keySize) {
            this.response = response;
            this.expiresAtMillis = expiresAtMillis;
            this.generation = generation;
            this.estimatedSize = keySize + response.estimatedSize() + 96L;
        }
    }

    private static final class InFlight {
        private final CompletableFuture<CachedHttpResponse> future = new CompletableFuture<>();
        private final long generation;

        private InFlight(long generation) {
            this.generation = generation;
        }
    }

    private final Config config;
    private final Object lock = new Object();
    private final LinkedHashMap<RequestDeduplicationKey, Entry> entries =
            new LinkedHashMap<>(16, 0.75f, true);
    private final Map<RequestDeduplicationKey, InFlight> inFlight = new HashMap<>();
    private final Map<String, Long> originGenerations = new HashMap<>();
    private final Map<String, Set<String>> structureByOrigin = new LinkedHashMap<>(16, 0.75f, true);

    private long estimatedBytes;
    private long structureBytes;
    private long requests;
    private long hits;
    private long coalescedHits;
    private long misses;
    private long expired;
    private long evicted;
    private long sideEffectInvalidations;
    private long structureInvalidations;

    public RequestDeduplicationCache(int maxEntries, long maxBytes, long ttlMillis) {
        this(new Config(maxEntries, maxBytes, ttlMillis, 0.25));
    }

    public RequestDeduplicationCache(Config config) {
        this.config = Objects.requireNonNull(config, "config");
    }

    /**
     * Returns a cached response or sends the request once and caches its response.
     *
     * @param key the request key.
     * @param sender the request sender.
     * @return the shared response.
     * @throws IOException if the request fails.
     */
    public CachedHttpResponse getOrSend(RequestDeduplicationKey key, RequestSender sender)
            throws IOException {
        return getOrSendResult(key, sender).getResponse();
    }

    /**
     * Returns a cached response or sends the request once and caches its response, indicating
     * whether the request was actually sent.
     *
     * @param key the request key.
     * @param sender the request sender.
     * @return the request result.
     * @throws IOException if the request fails.
     */
    public Result getOrSendResult(RequestDeduplicationKey key, RequestSender sender)
            throws IOException {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(sender, "sender");

        while (true) {
            long generationAtStart;
            InFlight requestInFlight = null;
            boolean sendRequest = false;
            synchronized (lock) {
                requests++;
                generationAtStart = generation(key.getOrigin());
                Entry entry = entries.get(key);
                if (entry != null) {
                    if (entry.expiresAtMillis <= System.currentTimeMillis()) {
                        removeEntry(key, entry);
                        expired++;
                    } else if (entry.generation != generationAtStart) {
                        removeEntry(key, entry);
                        sideEffectInvalidations++;
                    } else {
                        hits++;
                        return new Result(entry.response, false);
                    }
                }

                requestInFlight = inFlight.get(key);
                if (requestInFlight == null) {
                    requestInFlight = new InFlight(generationAtStart);
                    inFlight.put(key, requestInFlight);
                    sendRequest = true;
                } else if (requestInFlight.generation != generationAtStart) {
                    inFlight.remove(key);
                    requestInFlight = new InFlight(generationAtStart);
                    inFlight.put(key, requestInFlight);
                    sendRequest = true;
                }
            }

            if (sendRequest) {
                return new Result(send(key, sender, requestInFlight, generationAtStart), true);
            }

            try {
                CachedHttpResponse response = requestInFlight.future.get();
                synchronized (lock) {
                    if (generation(key.getOrigin()) == generationAtStart) {
                        coalescedHits++;
                        return new Result(response, false);
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while waiting for a deduplicated request.", e);
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof IOException) {
                    throw (IOException) cause;
                }
                if (cause instanceof RuntimeException) {
                    throw (RuntimeException) cause;
                }
                throw new IOException("Failed to send deduplicated request.", cause);
            } catch (CompletionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof IOException) {
                    throw (IOException) cause;
                }
                if (cause instanceof RuntimeException) {
                    throw (RuntimeException) cause;
                }
                throw new IOException("Failed to send deduplicated request.", cause);
            }
        }
    }

    private CachedHttpResponse send(
            RequestDeduplicationKey key,
            RequestSender sender,
            InFlight requestInFlight,
            long generationAtStart)
            throws IOException {
        try {
            CachedHttpResponse response = sender.send();
            synchronized (lock) {
                misses++;
                if (generation(key.getOrigin()) == generationAtStart) {
                    putEntry(
                            key,
                            new Entry(response, expiresAt(key), generationAtStart, keySize(key)));
                }
                inFlight.remove(key, requestInFlight);
            }
            requestInFlight.future.complete(response);
            return response;
        } catch (IOException | RuntimeException e) {
            synchronized (lock) {
                inFlight.remove(key, requestInFlight);
            }
            requestInFlight.future.completeExceptionally(e);
            throw e;
        }
    }

    /**
     * Records that the request changed server state and invalidates shared responses for the same
     * origin.
     *
     * @param message the request that caused the side effect.
     * @param mode the authentication mode used for the request.
     */
    public void recordSideEffect(HttpMessage message, RequestDeduplicationMode mode) {
        recordSideEffect(RequestDeduplicationKey.from(message, mode));
    }

    /**
     * Records that the given request key changed server state and invalidates all shared responses
     * for the request origin.
     *
     * @param key the request that caused the side effect.
     */
    public void recordSideEffect(RequestDeduplicationKey key) {
        Objects.requireNonNull(key, "key");
        String origin = normaliseOrigin(key.getOrigin());
        synchronized (lock) {
            originGenerations.put(origin, generation(origin) + 1);
            Iterator<Map.Entry<RequestDeduplicationKey, Entry>> iterator =
                    entries.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<RequestDeduplicationKey, Entry> entry = iterator.next();
                if (origin.equals(entry.getKey().getOrigin())) {
                    estimatedBytes -= entry.getValue().estimatedSize;
                    iterator.remove();
                    sideEffectInvalidations++;
                }
            }
        }
    }

    /**
     * Updates the endpoint structure for an origin.
     *
     * <p>When the proportion of changed endpoints exceeds the configured threshold all shared
     * responses for that origin are discarded, which prevents stale persistent entries from being
     * reused after a large site structure change.
     *
     * @param origin the request origin.
     * @param endpoints the endpoint signatures found in the current scan.
     * @return the ratio of changed endpoints, or {@code 0} when there was no previous structure.
     */
    public double updateStructure(String origin, Set<String> endpoints) {
        Objects.requireNonNull(origin, "origin");
        Objects.requireNonNull(endpoints, "endpoints");
        origin = normaliseOrigin(origin);

        Set<String> current = limitStructure(new HashSet<>(endpoints));
        double changeRatio;
        synchronized (lock) {
            Set<String> previous = structureByOrigin.get(origin);
            if (previous == null) {
                structureByOrigin.put(origin, current);
                structureBytes += estimateStructure(current);
                trimStructuresLocked();
                return 0;
            }

            int changed = 0;
            for (String endpoint : current) {
                if (!previous.contains(endpoint)) {
                    changed++;
                }
            }
            for (String endpoint : previous) {
                if (!current.contains(endpoint)) {
                    changed++;
                }
            }
            int total = Math.max(previous.size(), current.size());
            changeRatio = total == 0 ? 0 : changed / (double) total;

            structureBytes -= estimateStructure(previous);
            structureByOrigin.put(origin, current);
            structureBytes += estimateStructure(current);
            trimStructuresLocked();

            if (changeRatio > config.getStructureChangeThreshold()) {
                originGenerations.put(origin, generation(origin) + 1);
                Iterator<Map.Entry<RequestDeduplicationKey, Entry>> iterator =
                        entries.entrySet().iterator();
                while (iterator.hasNext()) {
                    Map.Entry<RequestDeduplicationKey, Entry> entry = iterator.next();
                    if (origin.equals(entry.getKey().getOrigin())) {
                        estimatedBytes -= entry.getValue().estimatedSize;
                        iterator.remove();
                        structureInvalidations++;
                    }
                }
            }
        }
        return changeRatio;
    }

    /**
     * Loads a persisted cache from the given file, if it exists.
     *
     * @param file the cache file.
     * @throws IOException if the file cannot be read.
     */
    public void load(Path file) throws IOException {
        Objects.requireNonNull(file, "file");
        if (!Files.isRegularFile(file)) {
            return;
        }
        try (InputStream input = Files.newInputStream(file);
                DataInputStream data = new DataInputStream(new BufferedInputStream(input))) {
            if (data.readInt() != FILE_MAGIC) {
                return;
            }
            int version = data.readInt();
            if (version != FILE_VERSION) {
                LOGGER.debug("Ignoring request deduplication cache with version {}.", version);
                return;
            }
            data.readLong();

            Map<String, Set<String>> loadedStructures = new HashMap<>();
            int structureCount = readCount(data);
            for (int i = 0; i < structureCount; i++) {
                String origin = readString(data);
                int endpointCount = readCount(data);
                Set<String> endpoints = new HashSet<>();
                for (int j = 0; j < endpointCount; j++) {
                    endpoints.add(readString(data));
                }
                loadedStructures.put(origin, endpoints);
            }

            int entryCount = readCount(data);
            List<Map.Entry<RequestDeduplicationKey, Entry>> loadedEntries = new ArrayList<>();
            long now = System.currentTimeMillis();
            for (int i = 0; i < entryCount; i++) {
                RequestDeduplicationKey key = RequestDeduplicationKey.deserialise(readString(data));
                long expiresAt = data.readLong();
                String header = readString(data);
                int bodyLength = data.readInt();
                if (bodyLength < 0 || bodyLength > MAX_SERIALISED_STRING) {
                    throw new IOException("Invalid cached response body length: " + bodyLength);
                }
                byte[] body = new byte[bodyLength];
                data.readFully(body);
                int timeElapsed = data.readInt();
                boolean fromTarget = data.readBoolean();
                if (expiresAt > now) {
                    CachedHttpResponse response =
                            new CachedHttpResponse(header, body, timeElapsed, fromTarget);
                    loadedEntries.add(
                            Map.entry(key, new Entry(response, expiresAt, 0, keySize(key))));
                }
            }

            synchronized (lock) {
                clearLocked();
                structureByOrigin.putAll(loadedStructures);
                structureBytes =
                        loadedStructures.values().stream()
                                .mapToLong(RequestDeduplicationCache::estimateStructure)
                                .sum();
                trimStructuresLocked();
                for (Map.Entry<RequestDeduplicationKey, Entry> loaded : loadedEntries) {
                    putEntry(loaded.getKey(), loaded.getValue());
                }
            }
        } catch (EOFException e) {
            throw new IOException("Unexpected end of request deduplication cache.", e);
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid request deduplication cache.", e);
        }
    }

    /**
     * Saves the current cache to the given file using an atomic replace when supported.
     *
     * @param file the cache file.
     * @throws IOException if the file cannot be written.
     */
    public void save(Path file) throws IOException {
        Objects.requireNonNull(file, "file");
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path temporary = file.resolveSibling(file.getFileName() + ".tmp");
        synchronized (lock) {
            try (OutputStream output = Files.newOutputStream(temporary);
                    DataOutputStream data =
                            new DataOutputStream(new BufferedOutputStream(output))) {
                data.writeInt(FILE_MAGIC);
                data.writeInt(FILE_VERSION);
                data.writeLong(System.currentTimeMillis());

                data.writeInt(structureByOrigin.size());
                for (Map.Entry<String, Set<String>> structure : structureByOrigin.entrySet()) {
                    writeString(data, structure.getKey());
                    data.writeInt(structure.getValue().size());
                    for (String endpoint : structure.getValue()) {
                        writeString(data, endpoint);
                    }
                }

                data.writeInt(entries.size());
                for (Map.Entry<RequestDeduplicationKey, Entry> cached : entries.entrySet()) {
                    writeString(data, cached.getKey().serialise());
                    Entry entry = cached.getValue();
                    data.writeLong(entry.expiresAtMillis);
                    writeString(data, entry.response.getHeader());
                    byte[] body = entry.response.getBody();
                    data.writeInt(body.length);
                    data.write(body);
                    data.writeInt(entry.response.getTimeElapsedMillis());
                    data.writeBoolean(entry.response.isResponseFromTargetHost());
                }
            }
        }

        try {
            Files.move(
                    temporary,
                    file,
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /**
     * Gets a snapshot of the current statistics.
     *
     * @return the statistics.
     */
    public RequestDeduplicationStats getStats() {
        synchronized (lock) {
            return new RequestDeduplicationStats(
                    requests,
                    hits,
                    coalescedHits,
                    misses,
                    expired,
                    evicted,
                    sideEffectInvalidations,
                    structureInvalidations,
                    entries.size(),
                    estimatedBytes + structureBytes);
        }
    }

    public int size() {
        synchronized (lock) {
            return entries.size();
        }
    }

    public long getEstimatedBytes() {
        synchronized (lock) {
            return estimatedBytes + structureBytes;
        }
    }

    /** Removes all cached responses and structures. */
    public void clear() {
        synchronized (lock) {
            clearLocked();
        }
    }

    private void clearLocked() {
        entries.clear();
        inFlight.clear();
        originGenerations.clear();
        structureByOrigin.clear();
        estimatedBytes = 0;
        structureBytes = 0;
    }

    private void putEntry(RequestDeduplicationKey key, Entry entry) {
        Entry replaced = entries.put(key, entry);
        if (replaced != null) {
            estimatedBytes -= replaced.estimatedSize;
        }
        estimatedBytes += entry.estimatedSize;

        Iterator<Map.Entry<RequestDeduplicationKey, Entry>> iterator =
                entries.entrySet().iterator();
        while ((entries.size() > config.getMaxEntries() || estimatedBytes > config.getMaxBytes())
                && iterator.hasNext()) {
            Map.Entry<RequestDeduplicationKey, Entry> eldest = iterator.next();
            estimatedBytes -= eldest.getValue().estimatedSize;
            iterator.remove();
            evicted++;
        }
    }

    private void removeEntry(RequestDeduplicationKey key, Entry entry) {
        if (entries.remove(key) != null) {
            estimatedBytes -= entry.estimatedSize;
        }
    }

    private long generation(String origin) {
        return originGenerations.getOrDefault(origin, 0L);
    }

    private Set<String> limitStructure(Set<String> endpoints) {
        if (endpoints.size() <= config.getMaxEntries()) {
            return endpoints;
        }
        Set<String> limited = new HashSet<>();
        endpoints.stream().sorted().limit(config.getMaxEntries()).forEach(limited::add);
        return limited;
    }

    private void trimStructuresLocked() {
        int endpointCount = structureByOrigin.values().stream().mapToInt(Set::size).sum();
        Iterator<Map.Entry<String, Set<String>>> iterator = structureByOrigin.entrySet().iterator();
        while (endpointCount > config.getMaxEntries()
                && structureByOrigin.size() > 1
                && iterator.hasNext()) {
            Map.Entry<String, Set<String>> eldest = iterator.next();
            endpointCount -= eldest.getValue().size();
            structureBytes -= estimateStructure(eldest.getValue());
            iterator.remove();
        }
    }

    private static long estimateStructure(Set<String> endpoints) {
        long bytes = 64;
        for (String endpoint : endpoints) {
            bytes += 64L + endpoint.length() * 2L;
        }
        return bytes;
    }

    private static String normaliseOrigin(String origin) {
        try {
            java.net.URI uri = java.net.URI.create(origin);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null) {
                return origin;
            }
            scheme = scheme.toLowerCase(java.util.Locale.ROOT);
            host = host.toLowerCase(java.util.Locale.ROOT);
            int port = uri.getPort();
            if (port == -1) {
                port = "https".equals(scheme) ? 443 : 80;
            }
            return scheme + "://" + host + ":" + port;
        } catch (IllegalArgumentException e) {
            return origin;
        }
    }

    private long expiresAt(RequestDeduplicationKey key) {
        return System.currentTimeMillis() + config.getTtlMillis();
    }

    private static long keySize(RequestDeduplicationKey key) {
        return 256L
                + key.getParameterNames().length()
                + key.getRequestFingerprint().length()
                + key.getAuthenticationFingerprint().length()
                + key.getVariantNamespace().length();
    }

    private static int readCount(DataInputStream data) throws IOException {
        int count = data.readInt();
        if (count < 0 || count > 10_000_000) {
            throw new IOException("Invalid request deduplication cache entry count: " + count);
        }
        return count;
    }

    private static String readString(DataInputStream data) throws IOException {
        int length = data.readInt();
        if (length < 0 || length > MAX_SERIALISED_STRING) {
            throw new IOException("Invalid request deduplication cache string length: " + length);
        }
        byte[] value = new byte[length];
        data.readFully(value);
        return new String(value, StandardCharsets.UTF_8);
    }

    private static void writeString(DataOutputStream data, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_SERIALISED_STRING) {
            throw new IOException("Request deduplication cache value is too large.");
        }
        data.writeInt(bytes.length);
        data.write(bytes);
    }
}
