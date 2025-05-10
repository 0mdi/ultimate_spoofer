#pragma once

#include "ext_traits.hpp"

#ifndef JM_STACK_STRING_HPP
#define JM_STACK_STRING_HPP

#define STACK_STRING(name, str)                                              \
    alignas(8) ext::decay_t<decltype(*str)>                                  \
        name[sizeof(str) / sizeof(ext::decay_t<decltype(*str)>)];            \
                                                                             \
    {                                                                        \
        constexpr ::jm::detail::string_storage<ext::decay_t<decltype(*str)>, \
                                               sizeof(str)>                  \
            _storageSTACK_STRING(str);                                       \
        _storageSTACK_STRING.copy(name);                                     \
    }

using _size_t = size_t;
using _uint64_t = unsigned long long;

namespace jm {
	namespace detail {

		template<_size_t N>
		struct _buffer_size {
			constexpr static _size_t value = N / 8 + static_cast<bool>(N % 8);
		};

		template<class CharT, _size_t N>
		struct string_storage {
			_uint64_t storage[_buffer_size<N>::value];

			inline constexpr string_storage(const CharT(&str)[N / sizeof(CharT)])
				: storage{ 0 }
			{
				// puts the string into 64 bit integer blocks in a constexpr way
				for (_size_t i = 0; i < N / sizeof(CharT); ++i)
					storage[i / (8 / sizeof(CharT))] |=
					(_uint64_t(str[i])
						<< ((i % (8 / sizeof(CharT))) * 8 * sizeof(CharT)));
			}

			template<_size_t I = 0>
			inline void copy(CharT* str, ext::integral_constant<_size_t, I> = {}) const
			{
				reinterpret_cast<volatile _uint64_t*>(str)[I] = storage[I];
				return copy(str, ext::integral_constant<_size_t, I + 1>{});
			}

			inline constexpr void
				copy(CharT*, ext::integral_constant<_size_t, _buffer_size<N>::value>) const
			{}
		};

	}
} // namespace jm::detail

#endif // include guard
