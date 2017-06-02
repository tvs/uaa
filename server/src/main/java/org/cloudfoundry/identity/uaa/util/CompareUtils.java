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

import java.util.Collection;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

public class CompareUtils {

    public static int compareToList(Collection<?> a, Collection<?> b) {
        return StringUtils.join(a, ',').compareTo(StringUtils.join(b, ','));
    }

    public static int compareToMap(Map<?,?> a, Map<?,?> b) {
        return compareToList(a.entrySet(), b.entrySet());
    }

}
