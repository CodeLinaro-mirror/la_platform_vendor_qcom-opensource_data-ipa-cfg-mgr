/*
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef DATA_IPA_CFG_MGR_UAPI_HELPER_H
#define DATA_IPA_CFG_MGR_UAPI_HELPER_H

#include  <type_traits>

class Reflection {

    private:

    struct HasTtlHelper { int ttl_update; };

public:

    /**
     * Types substitution succeeds in case ttl_update is defined in T, otherwise it fails. Leveraging SFINAE to make the
     * compiler choose the intended function version according to the type.
     * @tparam T type to
     */
    template <typename T>
    struct HasTtl : public T, HasTtlHelper {

        /**
         * In case ttl_update is defined in T there is an ambiguity since ttl_update is define in U and in T and thus,
         * types substitution fails. Otherwise, ttl_update is defined only in U and it succeeds. Leveraging SFINAE the
         * compilation is successful in either case.
         * @tparam U Fallback type in case ttl_update is not defined in T.
         * @return of std::false_type in case ttl_update is not defined in T, std::true_type otherwise.
         */
        template <typename U = HasTtl, typename = decltype(U::ttl_update)>
        static constexpr std::false_type stubForType (int);

        static constexpr std::true_type stubForType (long);

	using type = decltype(stubForType(0));

	static constexpr auto value = type::value;
    };
};

class UapiHelper {

public:

    /**
     * Set ttl_update to true in case it is defined in R, otherwise do nothing. Compiles regardless of whether
     * ttl_update is defined or not, providing compatibility to different Linux kernel versions without using C-style
     * pre-processor directives.
     * @tparam R IPA rule type, can be either routing or filtering rule.
     * @param r the rule being updated.
     */
    template <typename R, typename std::enable_if<Reflection::HasTtl<R>::value, bool>::type = 0>
    static inline void ruleTtlUpdateSet(R& r) { r.ttl_update = true; }

    template <typename R, typename std::enable_if<!Reflection::HasTtl<R>::value, bool>::type = 0>
    static inline void ruleTtlUpdateSet(R& r) { }
};

#endif //DATA_IPA_CFG_MGR_UAPI_HELPER_H
