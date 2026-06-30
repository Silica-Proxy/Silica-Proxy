/*
 * Copyright 2026 SilicaProxy Contributors
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


package com.silicaproxy.service.policy;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;

/**
 * Singleton Gitea container shared between GitOps sync integration tests.
 * The container and both repositories (public + private) are created once per JVM.
 */
class GiteaContainerSetup {

    static final String ADMIN_USER = "testadmin";
    static final String ADMIN_PASSWORD = "T3stP@ss!";
    static final String adminToken;
    static final String publicRepoUrl;
    static final String privateRepoUrl;
    static final Path publicGitopsDir;
    static final Path privateGitopsDir;
    static final Path privateNoTokenGitopsDir;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String BASE_URL;

    @SuppressWarnings("resource")
    private static final GenericContainer<?> GITEA =
            new GenericContainer<>(DockerImageName.parse("gitea/gitea:1.26"))
                    .withExposedPorts(3000)
                    .withEnv("GITEA__security__INSTALL_LOCK", "true")
                    .withEnv("GITEA__server__DOMAIN", "localhost")
                    .withEnv("GITEA__server__HTTP_PORT", "3000")
                    .withEnv("GITEA__database__DB_TYPE", "sqlite3")
                    .withEnv("GITEA__security__PASSWORD_COMPLEXITY", "off")
                    .withEnv("GITEA__log__LEVEL", "Error")
                    .waitingFor(Wait.forHttp("/api/v1/version").withStartupTimeout(Duration.ofMinutes(2)));

    static {
        GITEA.start();
        try {
            BASE_URL = "http://" + GITEA.getHost() + ":" + GITEA.getMappedPort(3000);

            // The gitea/gitea image runs PID 1 as root (USER root in the Dockerfile) and drops
            // to the 'git' user via su-exec in the entrypoint. We must do the same here because
            // the gitea binary refuses to run as root.
            Container.ExecResult result = GITEA.execInContainer(
                    "/sbin/su-exec", "git",
                    "gitea", "admin", "user", "create",
                    "--username", ADMIN_USER,
                    "--password", ADMIN_PASSWORD,
                    "--email", "admin@test.local",
                    "--admin"
            );
            if (result.getExitCode() != 0) {
                throw new IllegalStateException("Failed to create Gitea admin. stdout="
                        + result.getStdout() + " stderr=" + result.getStderr());
            }

            adminToken = createApiToken();

            String policyYaml = """
                    rules:
                      - package: "lodash"
                        version: "4.17.21"
                        action: "BLOCK"
                        reason: "CVE-2020-8203"
                      - package: "jquery"
                        version: "1.x"
                        action: "ALLOW"
                        reason: "Exception approved"
                    """;

            publicRepoUrl = createRepo("gitops-public", false);
            pushFile("gitops-public", "npm.yaml", policyYaml);
            publicGitopsDir = Files.createTempDirectory("gitops-public-");

            privateRepoUrl = createRepo("gitops-private", true);
            pushFile("gitops-private", "npm.yaml", policyYaml);
            privateGitopsDir = Files.createTempDirectory("gitops-private-");
            privateNoTokenGitopsDir = Files.createTempDirectory("gitops-private-notoken-");

        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static String createApiToken() throws Exception {
        String body = "{\"name\":\"ci-test-token\",\"scopes\":[\"read:repository\"]}";
        HttpResponse<String> response = post("/api/v1/users/" + ADMIN_USER + "/tokens", body);
        JsonNode json = JSON.readTree(response.body());
        return json.get("sha1").asText();
    }

    private static String createRepo(String repoName, boolean isPrivate) throws Exception {
        String body = "{\"name\":\"" + repoName + "\",\"private\":" + isPrivate
                + ",\"auto_init\":true,\"default_branch\":\"main\"}";
        post("/api/v1/user/repos", body);
        return BASE_URL + "/" + ADMIN_USER + "/" + repoName + ".git";
    }

    private static void pushFile(String repoName, String filename, String content) throws Exception {
        String encoded = Base64.getEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8));
        String body = "{\"message\":\"Add " + filename + "\",\"content\":\"" + encoded + "\"}";
        post("/api/v1/repos/" + ADMIN_USER + "/" + repoName + "/contents/" + filename, body);
    }

    private static HttpResponse<String> post(String path, String body) throws Exception {
        String credentials = ADMIN_USER + ":" + ADMIN_PASSWORD;
        String auth = "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        return HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .uri(URI.create(BASE_URL + path))
                        .header("Authorization", auth)
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );
    }
}
