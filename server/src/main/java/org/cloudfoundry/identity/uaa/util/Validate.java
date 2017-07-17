/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2017] VMware, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.util;

import java.util.HashSet;
import java.util.Set;

import org.springframework.util.StringUtils;

public class Validate {

    public static void validateOrderBy(String orderBy, String fields) throws IllegalArgumentException {
        if (!StringUtils.hasText(orderBy)) {
            return;
        }
        String[] input = StringUtils.commaDelimitedListToStringArray(orderBy);
        Set<String> compare = new HashSet<>();
        StringUtils.commaDelimitedListToSet(fields)
                .stream()
                .forEach(p -> compare.add(p.toLowerCase().trim()));
        boolean allints = true;
        for (String s : input) {
            try {
                Integer.parseInt(s);
            } catch (NumberFormatException e) {
                allints = false;
                if (!compare.contains(s.toLowerCase().trim())) {
                    throw new IllegalArgumentException("Invalid sort field:"+s);
                }
            }
        }
        if (allints) {
            return;
        }
    }

}
