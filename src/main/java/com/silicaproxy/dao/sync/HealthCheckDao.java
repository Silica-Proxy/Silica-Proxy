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


package com.silicaproxy.dao.sync;

import org.jspecify.annotations.NullMarked;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
@NullMarked
public class HealthCheckDao {

    private final JdbcClient jdbcClient;

    public HealthCheckDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public boolean isDatabaseReachable() {
        Integer result = jdbcClient.sql("SELECT 1").query(Integer.class).single();
        return result == 1;
    }
}
