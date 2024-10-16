/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */


package com.amazon.dlic.auth.http.jwt;

import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JWTUtils {

    private final static Logger log = LogManager.getLogger(JWTUtils.class);


    public static String[] extractRolesByPointer(Map<String,Object> claims, String rolesPointer) {
        if (rolesPointer == null) {
            log.warn("No roles_pointer configured, cannot extract roles from JWT.");
            return new String[0];
        }

        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.valueToTree(claims);
        JsonNode roles = root.at(rolesPointer);

        // We expect an array of strings.
        if (!roles.isArray()) {
            log.warn(
                    "Expected type Array for roles in the JWT for roles_pointer {}, but value was '{}' ({}).",
                    rolesPointer,
                    roles,
                    roles.getNodeType());
            return new String[0];
        }
        log.info("Extracted roles from JWT: {}", roles);

        return mapper.convertValue(roles, String[].class);
    }


}
