#pragma once

#include <cstdint>
#include "hash.hpp"

template<typename K, typename V>
class HashNode
{
public:
	V value;
	K key;

	void init(K key, V& value)
	{
		//this->value = value;
		//CALL_NO_RET(memcpy, &this->value, &value, sizeof(value));
		for (int i = 0, j = 1; i < sizeof(value); ++i)
		{
			auto ptr = ((uint8_t*)&this->value) + i;
			*ptr = *(((uint8_t*)&value) + i);
			++j; // avoid optimisation lol
		}

		this->key = key;
	}
};

template<typename K, typename V, uint32_t capacity>
class HashMap
{

public:
	HashNode<K, V> arr[capacity];
	int size;
	uint32_t _capacity = capacity;
	HashNode<K, V> dummy;

	void init()
	{
		size = 0;
		for (uint32_t i = 0; i < capacity; i++)
		{
			arr[i].key = -1;
		}
		//dummy.init(-1, {});
		//dummy.init(-1, -1);
	}

	hash32_t hashCode(K key)
	{
		return key % capacity;
	}

	void insertNode(K key, V& value)
	{
		HashNode<K, V> temp;
		temp.init(key, value);

		hash32_t hashIndex = hashCode(key);

		while (arr[hashIndex].key != key
			&& arr[hashIndex].key != -1)
		{
			hashIndex++;
			hashIndex %= capacity;
		}

		if (arr[hashIndex].key == -1)
			size++;

		//arr[hashIndex] = temp;
		//CALL_NO_RET(memcpy, &arr[hashIndex], &temp, sizeof(temp));
		for (int i = 0, j = 1; i < sizeof(temp); ++i)
		{
			auto ptr = ((uint8_t*)&arr[hashIndex]) + i;
			*ptr = *(((uint8_t*)&temp) + i);
			++j; // avoid optimisation lol
		}
	}


	V* get(hash32_t key)
	{
		hash32_t hashIndex = hashCode(key);
		int counter = 0;
		while (arr[hashIndex].key != -1)
		{
			uint32_t counter = 0;
			if (counter++ > capacity)
				return nullptr;

			if (arr[hashIndex].key == key)
				return &arr[hashIndex].value;

			hashIndex++;
			hashIndex %= capacity;
		}

		return nullptr;
	}

	//Return current size  
	int sizeofMap()
	{
		return size;
	}

	//Return true if size is 0 
	bool isEmpty()
	{
		return size == 0;
	}

};
