#pragma once
#include <intrin.h>

struct mutex
{
	volatile char _p = FALSE;

	__forceinline void lock()
	{
		while (_InterlockedCompareExchange8(&_p, TRUE, FALSE)) _mm_pause();
	}

	__forceinline bool try_lock()
	{
		return !_InterlockedCompareExchange8(&_p, TRUE, FALSE);
	}

	__forceinline void unlock()
	{
		_p = FALSE;
	}
};

template<bool raise_irql>
struct lock_guard
{
	mutex& mtx;
	int irql_old = 0;

	__forceinline lock_guard(mutex& mtx) : mtx(mtx)
	{
		if (raise_irql)
		{
			irql_old = __readcr8();
			if (irql_old < DISPATCH_LEVEL)
				__writecr8(DISPATCH_LEVEL);
		}
		mtx.lock();
	}

	__forceinline ~lock_guard()
	{
		mtx.unlock();
		if (raise_irql)
		{
			__writecr8(irql_old);
		}
	}
};