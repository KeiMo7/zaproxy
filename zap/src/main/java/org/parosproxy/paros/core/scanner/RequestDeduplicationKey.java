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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.users.User;

/**
 * Immutable key used to identify requests whose response can be shared.
 *
 * <p>The key deliberately contains more than the URL and parameter names: the canonical request
 * data (including parameter values and the request body) is hashed so injection payload variants
 * cannot be mixed. Authentication values are included for session-based requests, while {@link
 * RequestDeduplicationMode#STATELESS} records only whether authentication was present.
 *
 * @since 2.18.0
 */
public final class RequestDeduplicationKey {

    private static final Set<String> IGNORED_HEADERS = new HashSet<>();

    static {
        Collections.addAll(
                IGNORED_HEADERS,
                "host",
                HttpHeader.CONTENT_LENGTH,
                HttpHeader.TRANSFER_ENCODING,
                HttpHeader.CONNECTION,
                HttpHeader.PROXY_CONNECTION,
                HttpHeader.USER_AGENT,
                HttpHeader.IF_MODIFIED_SINCE,
                HttpHeader.IF_NONE_MATCH,
                "date",
                HttpHeader.ACCEPT_ENCODING,
                HttpHeader.CACHE_CONTROL,
                HttpHeader.PRAGMA,
                HttpHeader.X_ZAP_SCAN_ID,
                HttpHeader.X_ZAP_REQUESTID,
                HttpHeader.X_ZAP_API_KEY,
                HttpHeader.X_ZAP_API_NONCE);
    }

    private static final Set<String> AUTH_HEADERS = new HashSet<>();

    static {
        Collections.addAll(
                AUTH_HEADERS,
                HttpHeader.COOKIE,
                HttpHeader.AUTHORIZATION,
                HttpHeader.PROXY_AUTHORIZATION,
                HttpHeader.X_CSRF_TOKEN,
                HttpHeader.X_CSRFTOKEN,
                HttpHeader.X_XSRF_TOKEN);
    }

    private final String method;
    private final String scheme;
    private final String host;
    private final int port;
    private final String path;
    private final String parameterNames;
    private final String requestFingerprint;
    private final String authenticationFingerprint;
    private final boolean authenticationPresent;
    private final String variantNamespace;

    private RequestDeduplicationKey(
            String method,
            String scheme,
            String host,
            int port,
            String path,
            String parameterNames,
            String requestFingerprint,
            String authenticationFingerprint,
            boolean authenticationPresent,
            String variantNamespace) {
        this.method = method;
        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.path = path;
        this.parameterNames = parameterNames;
        this.requestFingerprint = requestFingerprint;
        this.authenticationFingerprint = authenticationFingerprint;
        this.authenticationPresent = authenticationPresent;
        this.variantNamespace = variantNamespace;
    }

    /**
     * Creates a key for the given message.
     *
     * @param message the request message, must not be {@code null}.
     * @param mode the authentication mode, must not be {@code null}.
     * @return the key.
     */
    public static RequestDeduplicationKey from(HttpMessage message, RequestDeduplicationMode mode) {
        return from(message, mode, "");
    }

    /**
     * Creates a key for the given message and variant namespace.
     *
     * <p>The namespace can be used by a plugin to keep otherwise identical requests in separate
     * variant domains.
     *
     * @param message the request message, must not be {@code null}.
     * @param mode the authentication mode, must not be {@code null}.
     * @param variantNamespace a namespace for the request variant, may be empty.
     * @return the key.
     */
    public static RequestDeduplicationKey from(
            HttpMessage message, RequestDeduplicationMode mode, String variantNamespace) {
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(mode, "mode");

        HttpRequestHeader header = message.getRequestHeader();
        URI uri = header.getURI();
        String scheme = normaliseScheme(uri);
        String host = obtainHost(uri);
        int port = effectivePort(uri, scheme);
        String path = uri.getEscapedPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }

        String query = extractQuery(uri);
        String contentType = header.getHeader(HttpHeader.CONTENT_TYPE);
        String body = message.getRequestBody().toString();
        Set<String> parameterNames = new TreeSet<>();
        parameterNames.addAll(extractParameterNames(query));

        List<String> queryPairs = canonicalPairs(query);
        String canonicalRequest;
        if (isFormUrlEncoded(contentType)) {
            List<String> formPairs = canonicalPairs(body);
            parameterNames.addAll(extractParameterNames(body));
            canonicalRequest =
                    "query="
                            + String.join("&", queryPairs)
                            + "\nform="
                            + String.join("&", formPairs);
        } else {
            canonicalRequest =
                    "query="
                            + String.join("&", queryPairs)
                            + "\nbody="
                            + sha256(message.getRequestBody().getBytes());
        }

        String authenticationFingerprint = "";
        boolean authenticationPresent = false;
        List<String> semanticHeaders = new ArrayList<>();
        for (HttpHeaderField field : header.getHeaders()) {
            String name = field.getName().toLowerCase(Locale.ROOT);
            if (IGNORED_HEADERS.contains(name)) {
                continue;
            }
            boolean authHeader = AUTH_HEADERS.contains(name);
            if (authHeader) {
                authenticationPresent = true;
                if (mode == RequestDeduplicationMode.STATELESS) {
                    continue;
                }
            }
            semanticHeaders.add(name + ":" + normalise(field.getValue()));
        }
        Collections.sort(semanticHeaders);

        User user = message.getRequestingUser();
        if (user != null && user.getName() != null) {
            authenticationPresent = true;
            authenticationFingerprint = "user:" + user.getName();
        }
        if (authenticationPresent && !authenticationFingerprint.isEmpty()) {
            semanticHeaders.add(authenticationFingerprint);
        }
        Collections.sort(semanticHeaders);

        String authContext;
        if (mode == RequestDeduplicationMode.STATELESS) {
            authContext = authenticationPresent ? "authenticated" : "anonymous";
        } else {
            authContext = sha256(String.join("\n", semanticHeaders));
        }

        if (authenticationFingerprint.isEmpty()) {
            authenticationFingerprint =
                    authenticationPresent ? "present:" + authContext : "anonymous";
        }

        String requestFingerprint =
                sha256(
                        String.join(
                                "\n",
                                method(header),
                                scheme,
                                host,
                                Integer.toString(port),
                                path,
                                canonicalRequest,
                                String.join("\u0000", semanticHeaders),
                                mode.name()));

        return new RequestDeduplicationKey(
                method(header),
                scheme,
                host,
                port,
                path,
                String.join("\u0000", parameterNames),
                requestFingerprint,
                authenticationPresent ? authenticationFingerprint : "anonymous",
                authenticationPresent,
                variantNamespace == null ? "" : variantNamespace);
    }

    /**
     * Creates a structure signature for the given message. Unlike a full request key this ignores
     * parameter values, allowing structure changes to be detected without treating changed values
     * as changed endpoints.
     *
     * @param message the request message, must not be {@code null}.
     * @return the structure signature.
     */
    public static String endpointSignature(HttpMessage message) {
        Objects.requireNonNull(message, "message");
        HttpRequestHeader header = message.getRequestHeader();
        URI uri = header.getURI();
        String scheme = normaliseScheme(uri);
        String host = obtainHost(uri);
        int port = effectivePort(uri, scheme);
        String path = uri.getEscapedPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }

        Set<String> names = new TreeSet<>(extractParameterNames(extractQuery(uri)));
        if (isFormUrlEncoded(header.getHeader(HttpHeader.CONTENT_TYPE))) {
            names.addAll(extractParameterNames(message.getRequestBody().toString()));
        }
        boolean auth = hasAuthentication(header) || message.getRequestingUser() != null;
        return method(header)
                + "\n"
                + scheme
                + "\n"
                + host
                + "\n"
                + port
                + "\n"
                + path
                + "\n"
                + String.join("\u0000", names)
                + "\n"
                + auth;
    }

    private static String method(HttpRequestHeader header) {
        return header.getMethod().toUpperCase(Locale.ROOT);
    }

    private static String normaliseScheme(URI uri) {
        String scheme = uri.getScheme();
        return scheme == null || scheme.isEmpty()
                ? HttpHeader.HTTP
                : scheme.toLowerCase(Locale.ROOT);
    }

    private static String obtainHost(URI uri) {
        try {
            String host = uri.getHost();
            return host == null ? "" : host.toLowerCase(Locale.ROOT);
        } catch (URIException e) {
            throw new IllegalArgumentException("Failed to obtain the request host.", e);
        }
    }

    private static int effectivePort(URI uri, String scheme) {
        int port = uri.getPort();
        if (port != -1) {
            return port;
        }
        return HttpHeader.HTTPS.equalsIgnoreCase(scheme) ? 443 : 80;
    }

    private static String extractQuery(URI uri) {
        String pathQuery = uri.getEscapedPathQuery();
        if (pathQuery == null) {
            return "";
        }
        int index = pathQuery.indexOf('?');
        return index == -1 ? "" : pathQuery.substring(index + 1);
    }

    private static Set<String> extractParameterNames(String encodedParameters) {
        Set<String> names = new TreeSet<>();
        if (encodedParameters == null || encodedParameters.isEmpty()) {
            return names;
        }
        for (String pair : encodedParameters.split("[&;]")) {
            if (pair.isEmpty()) {
                continue;
            }
            int index = pair.indexOf('=');
            String name = index == -1 ? pair : pair.substring(0, index);
            names.add(decodeParameter(name));
        }
        return names;
    }

    private static List<String> canonicalPairs(String encodedParameters) {
        List<String> pairs = new ArrayList<>();
        if (encodedParameters == null || encodedParameters.isEmpty()) {
            return pairs;
        }
        for (String pair : encodedParameters.split("[&;]")) {
            if (!pair.isEmpty()) {
                pairs.add(pair);
            }
        }
        Collections.sort(pairs);
        return pairs;
    }

    private static String decodeParameter(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException | IllegalArgumentException e) {
            return value;
        }
    }

    private static boolean isFormUrlEncoded(String contentType) {
        return contentType != null
                && contentType
                        .trim()
                        .toLowerCase(Locale.ROOT)
                        .startsWith(HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
    }

    private static boolean hasAuthentication(HttpRequestHeader header) {
        for (HttpHeaderField field : header.getHeaders()) {
            if (AUTH_HEADERS.contains(field.getName().toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static String normalise(String value) {
        return value == null ? "" : value.trim();
    }

    static String sha256(byte[] value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return toHex(digest.digest(value));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available.", e);
        }
    }

    static String sha256(String value) {
        return sha256(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String toHex(byte[] value) {
        StringBuilder hex = new StringBuilder(value.length * 2);
        for (byte b : value) {
            hex.append(Character.forDigit((b >>> 4) & 0xf, 16));
            hex.append(Character.forDigit(b & 0xf, 16));
        }
        return hex.toString();
    }

    public String getMethod() {
        return method;
    }

    public String getScheme() {
        return scheme;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public String getPath() {
        return path;
    }

    /**
     * Gets the sorted parameter names included in the key, separated by NUL characters.
     *
     * @return the parameter names.
     */
    public String getParameterNames() {
        return parameterNames;
    }

    public String getRequestFingerprint() {
        return requestFingerprint;
    }

    public boolean isAuthenticationPresent() {
        return authenticationPresent;
    }

    public String getAuthenticationFingerprint() {
        return authenticationFingerprint;
    }

    public String getVariantNamespace() {
        return variantNamespace;
    }

    /**
     * Gets the request origin in {@code scheme://host:port} form.
     *
     * @return the origin.
     */
    public String getOrigin() {
        return scheme + "://" + host + ":" + port;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                method,
                scheme,
                host,
                port,
                path,
                parameterNames,
                requestFingerprint,
                authenticationFingerprint,
                variantNamespace);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RequestDeduplicationKey)) {
            return false;
        }
        RequestDeduplicationKey other = (RequestDeduplicationKey) obj;
        return port == other.port
                && authenticationPresent == other.authenticationPresent
                && Objects.equals(method, other.method)
                && Objects.equals(scheme, other.scheme)
                && Objects.equals(host, other.host)
                && Objects.equals(path, other.path)
                && Objects.equals(parameterNames, other.parameterNames)
                && Objects.equals(requestFingerprint, other.requestFingerprint)
                && Objects.equals(authenticationFingerprint, other.authenticationFingerprint)
                && Objects.equals(variantNamespace, other.variantNamespace);
    }

    @Override
    public String toString() {
        return method
                + " "
                + getOrigin()
                + path
                + " params="
                + parameterNames
                + " auth="
                + (authenticationPresent ? "yes" : "no")
                + (variantNamespace.isEmpty() ? "" : " variant=" + variantNamespace);
    }

    String serialise() {
        return encode(method)
                + "\n"
                + encode(scheme)
                + "\n"
                + encode(host)
                + "\n"
                + encode(Integer.toString(port))
                + "\n"
                + encode(path)
                + "\n"
                + encode(parameterNames)
                + "\n"
                + encode(requestFingerprint)
                + "\n"
                + encode(authenticationFingerprint)
                + "\n"
                + encode(Boolean.toString(authenticationPresent))
                + "\n"
                + encode(variantNamespace);
    }

    static RequestDeduplicationKey deserialise(String value) {
        String[] parts = value.split("\n", -1);
        if (parts.length != 10) {
            throw new IllegalArgumentException("Invalid request deduplication key.");
        }
        return new RequestDeduplicationKey(
                decode(parts[0]),
                decode(parts[1]),
                decode(parts[2]),
                Integer.parseInt(decode(parts[3])),
                decode(parts[4]),
                decode(parts[5]),
                decode(parts[6]),
                decode(parts[7]),
                Boolean.parseBoolean(decode(parts[8])),
                decode(parts[9]));
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String decode(String value) {
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }
}
