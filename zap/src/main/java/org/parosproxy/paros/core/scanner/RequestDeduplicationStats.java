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

/**
 * Immutable request deduplication statistics.
 *
 * @since 2.18.0
 */
public final class RequestDeduplicationStats {

    private final long requests;
    private final long hits;
    private final long coalescedHits;
    private final long misses;
    private final long expired;
    private final long evicted;
    private final long sideEffectInvalidations;
    private final long structureInvalidations;
    private final int entries;
    private final long estimatedBytes;

    RequestDeduplicationStats(
            long requests,
            long hits,
            long coalescedHits,
            long misses,
            long expired,
            long evicted,
            long sideEffectInvalidations,
            long structureInvalidations,
            int entries,
            long estimatedBytes) {
        this.requests = requests;
        this.hits = hits;
        this.coalescedHits = coalescedHits;
        this.misses = misses;
        this.expired = expired;
        this.evicted = evicted;
        this.sideEffectInvalidations = sideEffectInvalidations;
        this.structureInvalidations = structureInvalidations;
        this.entries = entries;
        this.estimatedBytes = estimatedBytes;
    }

    public long getRequests() {
        return requests;
    }

    public long getHits() {
        return hits;
    }

    public long getCoalescedHits() {
        return coalescedHits;
    }

    /**
     * Gets all hits, including results shared by requests already in flight.
     *
     * @return the total deduplication hits.
     */
    public long getDeduplicationHits() {
        return hits + coalescedHits;
    }

    public long getMisses() {
        return misses;
    }

    /**
     * Gets the estimated hit rate in the range {@code 0.0} to {@code 1.0}.
     *
     * @return the hit rate.
     */
    public double getHitRate() {
        return requests == 0 ? 0 : getDeduplicationHits() / (double) requests;
    }

    public long getExpired() {
        return expired;
    }

    public long getEvicted() {
        return evicted;
    }

    public long getSideEffectInvalidations() {
        return sideEffectInvalidations;
    }

    public long getStructureInvalidations() {
        return structureInvalidations;
    }

    public int getEntries() {
        return entries;
    }

    /**
     * Gets the estimated memory used by the index, including cached response bodies.
     *
     * @return the estimated number of bytes.
     */
    public long getEstimatedBytes() {
        return estimatedBytes;
    }

    @Override
    public String toString() {
        return "requests="
                + requests
                + ", hits="
                + getDeduplicationHits()
                + ", hitRate="
                + String.format("%.2f", getHitRate())
                + ", misses="
                + misses
                + ", expired="
                + expired
                + ", evicted="
                + evicted
                + ", sideEffectInvalidations="
                + sideEffectInvalidations
                + ", structureInvalidations="
                + structureInvalidations
                + ", entries="
                + entries
                + ", estimatedBytes="
                + estimatedBytes;
    }
}
