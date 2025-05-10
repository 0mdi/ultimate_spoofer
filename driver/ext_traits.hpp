#pragma once

namespace ext
{
	// STRUCT TEMPLATE integral_constant
	template <class _Ty,
		_Ty _Val>
		struct integral_constant { // convenient template for integral constant types
		static constexpr _Ty value = _Val;

		using value_type = _Ty;
		using type = integral_constant;

		constexpr operator value_type() const noexcept { // return stored value
			return value;
		}

		constexpr value_type operator()() const noexcept { // return stored value
			return value;
		}
	};
	template <bool _Val>
	using bool_constant = integral_constant<bool, _Val>;

	using true_type = bool_constant<true>;
	using false_type = bool_constant<false>;

	// STRUCT TEMPLATE conditional
	template <bool _Test, class _Ty1,
		class _Ty2>
		struct conditional { // type is _Ty2 for assumed !_Test
		using type = _Ty2;
	};

	template <class _Ty1, class _Ty2>
	struct conditional<true, _Ty1, _Ty2> { // type is _Ty1 for _Test
		using type = _Ty1;
	};

	template <bool _Test, class _Ty1, class _Ty2>
	using conditional_t = typename conditional<_Test, _Ty1, _Ty2>::type;

	// STRUCT TEMPLATE remove_reference
	template <class _Ty>
	struct remove_reference { // remove reference
		using type = _Ty;
	};

	template <class _Ty>
	struct remove_reference<_Ty&> { // remove reference
		using type = _Ty;
	};

	template <class _Ty>
	struct remove_reference<_Ty&&> { // remove rvalue reference
		using type = _Ty;
	};

	template <class _Ty>
	using remove_reference_t = typename remove_reference<_Ty>::type;

	// STRUCT TEMPLATE remove_pointer
	template <class _Ty>
	struct remove_pointer { // remove pointer
		using type = _Ty;
	};

	template <class _Ty>
	using remove_pointer_t = typename remove_pointer<_Ty>::type;

	// STRUCT TEMPLATE remove_cv
	template <class _Ty>
	struct remove_cv { // remove top level const and volatile qualifiers
		using type = _Ty;
	};

	template <class _Ty>
	struct remove_cv<const _Ty> { // remove top level const and volatile qualifiers
		using type = _Ty;
	};

	template <class _Ty>
	struct remove_cv<volatile _Ty> { // remove top level const and volatile qualifiers
		using type = _Ty;
	};

	template <class _Ty>
	struct remove_cv<const volatile _Ty> { // remove top level const and volatile qualifiers
		using type = _Ty;
	};

	template <class _Ty>
	using remove_cv_t = typename remove_cv<_Ty>::type;

	// STRUCT TEMPLATE add_pointer
	template <class _Ty,
		class = void>
		struct _Add_pointer { // add pointer
		using type = _Ty;
	};

	// ALIAS TEMPLATE void_t
	template <class... _Types>
	using void_t = void;

	template <class _Ty>
	struct _Add_pointer<_Ty, void_t<remove_reference_t<_Ty>*>> { // add pointer
		using type = remove_reference_t<_Ty>*;
	};

	template <class _Ty>
	struct add_pointer { // add pointer
		using type = typename _Add_pointer<_Ty>::type;
	};

	template <class _Ty>
	using add_pointer_t = typename _Add_pointer<_Ty>::type;
	template <class _Ty>
	struct is_array : false_type { // determine whether _Ty is an array
	};

	template <class _Ty, size_t _Nx>
	struct is_array<_Ty[_Nx]> : true_type { // determine whether _Ty is an array
	};

	template <class _Ty>
	struct is_array<_Ty[]> : true_type { // determine whether _Ty is an array
	};

	template <class _Ty>
	constexpr bool is_array_v = is_array<_Ty>::value;

	// STRUCT TEMPLATE is_function
	template <class _Ty>
	struct _Is_function { // determine whether _Ty is a function
		using _Bool_type = false_type;
	};
	template <class _Ty>
	struct is_function : _Is_function<_Ty>::_Bool_type { // determine whether _Ty is a function
	};

	template <class _Ty>
	constexpr bool is_function_v = is_function<_Ty>::value;


	// STRUCT TEMPLATE remove_extent
	template <class _Ty>
	struct remove_extent { // remove array extent
		using type = _Ty;
	};

	template <class _Ty, size_t _Ix>
	struct remove_extent<_Ty[_Ix]> { // remove array extent
		using type = _Ty;
	};

	template <class _Ty>
	struct remove_extent<_Ty[]> { // remove array extent
		using type = _Ty;
	};

	template <class _Ty>
	using remove_extent_t = typename remove_extent<_Ty>::type;

	// STRUCT TEMPLATE decay
	template <class _Ty>
	struct decay { // determines decayed version of _Ty
		using _Ty1 = remove_reference_t<_Ty>;

		using type = conditional_t<is_array_v<_Ty1>, add_pointer_t<remove_extent_t<_Ty1>>,
			conditional_t<is_function_v<_Ty1>, add_pointer_t<_Ty1>, remove_cv_t<_Ty1>>>;
	};

	template <class _Ty>
	using decay_t = typename decay<_Ty>::type;
}