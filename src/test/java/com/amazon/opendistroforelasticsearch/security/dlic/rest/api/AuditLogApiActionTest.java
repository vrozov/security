/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.AbstractAuditlogiUnitTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage;
import com.amazon.opendistroforelasticsearch.security.auditlog.integration.TestAuditlogImpl;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;

import org.elasticsearch.common.settings.Settings;

import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

public class AuditLogApiActionTest extends AbstractAuditlogiUnitTest {
    private static final String ENDPOINT = "/_opendistro/_security/api/_auditlog";

    private static class AuditLogApiTestRequestContent extends AuditLogApiAction.AuditLogApiRequestContent {
        @JsonProperty("unknown")
        private String unknown;

        AuditLogApiTestRequestContent(AuditCategory auditCategory, String effectiveUser, String privilege, Map<String, List<String>> headers, String remoteAddress) {
            super(auditCategory, effectiveUser, privilege, headers, remoteAddress);
        }

        AuditLogApiTestRequestContent(AuditCategory auditCategory, String unknown) {
            super(auditCategory, null, null, null, null);
            this.unknown = unknown;
        }
    }

    private static void assertMsg(AuditCategory auditCategory, String effectiveUser, AuditMessage message) {
        Assert.assertEquals(auditCategory, message.getCategory());
        Assert.assertEquals(effectiveUser, message.getEffectiveUser());
        Assert.assertEquals(AuditLog.Origin.REST, message.getAsMap().get("audit_request_layer"));
    }

    @Test
    public void testAuditLog() throws Exception {
        Settings additionalSettings = Settings.builder()
                .put("opendistro_security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS, ENDPOINT)
                .build();
        setup(additionalSettings);

        rh.sendAdminCertificate = true;
        rh.keystore = "auditlog/kirk-keystore.jks";

        AuditLogApiAction.AuditLogApiRequestContent content;
        String body;
        RestHelper.HttpResponse response;

        content = new AuditLogApiTestRequestContent(
                AuditCategory.BAD_HEADERS,
                null,
                null,
                ImmutableMap.of("Bad Header", ImmutableList.of("header1", "header2")),
                "192.168.1.0:80"
        );
        body = DefaultObjectMapper.writeValueAsString(content, false);

        TestAuditlogImpl.clear();

        response = rh.executePostRequest(ENDPOINT, body);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        assertMsg(AuditCategory.BAD_HEADERS, null, TestAuditlogImpl.messages.get(0));

        content = new AuditLogApiTestRequestContent(
            AuditCategory.FAILED_LOGIN,
            "unknown",
            null,
            ImmutableMap.of("Authentication", ImmutableList.of("Basic: abcdef")),
            "192.168.1.0:80");
        body = DefaultObjectMapper.writeValueAsString(content, false);

        TestAuditlogImpl.clear();

        response = rh.executePostRequest(ENDPOINT, body);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        assertMsg(AuditCategory.FAILED_LOGIN, "unknown", TestAuditlogImpl.messages.get(0));

        content = new AuditLogApiTestRequestContent(
                AuditCategory.MISSING_PRIVILEGES,
                "unknown",
                null,
                ImmutableMap.of("Authentication", ImmutableList.of("Basic: abcdef")),
                "192.168.1.0:80");
        body = DefaultObjectMapper.writeValueAsString(content, false);

        TestAuditlogImpl.clear();

        response = rh.executePostRequest(ENDPOINT, body);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        assertMsg(AuditCategory.MISSING_PRIVILEGES, "unknown", TestAuditlogImpl.messages.get(0));

        content = new AuditLogApiTestRequestContent(
                AuditCategory.SSL_EXCEPTION,
                null,
                null,
                ImmutableMap.of("Authentication", ImmutableList.of("Basic: abcdef")),
                "192.168.1.0:80");
        body = DefaultObjectMapper.writeValueAsString(content, false);

        TestAuditlogImpl.clear();

        response = rh.executePostRequest(ENDPOINT, body);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        assertMsg(AuditCategory.SSL_EXCEPTION, null, TestAuditlogImpl.messages.get(0));

        content = new AuditLogApiTestRequestContent(
                AuditCategory.AUTHENTICATED,
                "user",
                null,
                ImmutableMap.of("Authentication", ImmutableList.of("Basic: abcdef")),
                "192.168.1.0:80");
        body = DefaultObjectMapper.writeValueAsString(content, false);

        TestAuditlogImpl.clear();

        response = rh.executePostRequest(ENDPOINT, body);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        assertMsg(AuditCategory.AUTHENTICATED, "user", TestAuditlogImpl.messages.get(0));
    }

    @Test
    public void testNotSuperAdminUnauthorized() throws Exception {
        Settings additionalSettings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_RESTAPI_ROLES_ENABLED, "opendistro_security_all_access")
                .build();
        setup(additionalSettings);

        rh.sendAdminCertificate = false;

        RestHelper.HttpResponse response;

        response = rh.executePostRequest(ENDPOINT, null, encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Assert.assertEquals("User is not authorized to log audit message", DefaultObjectMapper.readTree(response.getBody()).get("message").asText());
    }

    @Test
    public void testInvalidMethod() throws Exception {
        setup(Settings.EMPTY);

        rh.sendAdminCertificate = true;
        rh.keystore = "auditlog/kirk-keystore.jks";

        RestHelper.HttpResponse response;

        response = rh.executeGetRequest(ENDPOINT);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT, null);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executeDeleteRequest(ENDPOINT);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

    }

    @Test
    public void testNoEffectiveUser() throws Exception {
        setup(Settings.EMPTY);

        rh.sendAdminCertificate = true;
        rh.keystore = "auditlog/kirk-keystore.jks";

        AuditLogApiAction.AuditLogApiRequestContent content;
        String body;
        RestHelper.HttpResponse response;

        content = new AuditLogApiTestRequestContent(
                AuditCategory.FAILED_LOGIN,
                null,
                null,
                ImmutableMap.of("Authentication", ImmutableList.of("Basic: abcdef")),
                "192.168.1.0:80");
        body = DefaultObjectMapper.writeValueAsString(content, false);

        response = rh.executePostRequest(ENDPOINT, body);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals("user is required", DefaultObjectMapper.readTree(response.getBody()).get("message").asText());

        content = new AuditLogApiTestRequestContent(
                AuditCategory.MISSING_PRIVILEGES,
                null,
                null,
                ImmutableMap.of("Authentication", ImmutableList.of("Basic: abcdef")),
                "192.168.1.0:80");
        body = DefaultObjectMapper.writeValueAsString(content, false);

        response = rh.executePostRequest(ENDPOINT, body);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals("user is required", DefaultObjectMapper.readTree(response.getBody()).get("message").asText());

        content = new AuditLogApiTestRequestContent(
                AuditCategory.AUTHENTICATED,
                null,
                null,
                ImmutableMap.of("Authentication", ImmutableList.of("Basic: abcdef")),
                "192.168.1.0:80");
        body = DefaultObjectMapper.writeValueAsString(content, false);

        response = rh.executePostRequest(ENDPOINT, body);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals("user is required", DefaultObjectMapper.readTree(response.getBody()).get("message").asText());

    }

    @Test
    public void testBadRequest() throws Exception {
        setup(Settings.EMPTY);

        rh.sendAdminCertificate = true;
        rh.keystore = "auditlog/kirk-keystore.jks";

        AuditLogApiAction.AuditLogApiRequestContent content;
        String body;
        RestHelper.HttpResponse response;

        content = new AuditLogApiTestRequestContent(
                AuditCategory.FAILED_LOGIN,
                "192.168.1.0:80");
        body = DefaultObjectMapper.writeValueAsString(content, false);

        response = rh.executePostRequest(ENDPOINT, body);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }

}
