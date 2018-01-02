#ifndef _HASHSET_H_
#define _HASHSET_H_

/*
 * Copyright (c) 2017, University of Oregon
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:

 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * - Neither the name of the University of Oregon nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * interface definition for generic hashset implementation
 *
 * patterned roughly after Java 6 HashSet generic class
 */

typedef struct hashset HashSet;	/* opaque type definition */

/*
 * create a hashset with the specified capacity and load factor;
 * if capacity == 0, a default initial capacity (16 elements) is used
 * if loadFactor == 0.0, a default load factor (0.75) is used
 * if number of elements/number of buckets exceeds the load factor, the
 * table is resized, doubling the number of buckets, up to a max number
 * of buckets (134,217,728)
 *
 * cmpFunction is used to determine equality between two objects, with
 * `cmpFunction(first, second)' returning 0 if first==second, <>0 otherwise
 *
 * hashFunction is used to hash a value into the hash table that underlies
 * the set, with `hashFunction(value, N)' returning a number in [0,N)
 *
 * returns a pointer to the hashset, or NULL if there are malloc() errors
 */
HashSet *hs_create(int (*cmpFunction)(void *, void *),
                   long (*hashFunction)(void *, long),
                   long capacity, double loadFactor);

/*
 * destroys the hashset; for each element, if userFunction != NULL,
 * it is invoked on the element; the storage associated with
 * the hashset is then returned to the heap
 */
void hs_destroy(HashSet *hs, void (*userFunction)(void *element));

/*
 * clears all elements from the hashset; for each element,
 * if userFunction != NULL, it is invoked on the element;
 * any storage associated with the entry in the hashset is then
 * returned to the heap
 *
 * upon return, the hashset will be empty
 */
void hs_clear(HashSet *hs, void (*userFunction)(void *element));

/*
 * adds the specified element to the set if it is not already present
 *
 * returns 1 if the element was added, 0 if the element was already present
 */
int hs_add(HashSet *hs, void *element);

/*
 * returns 1 if the set contains the specified element, 0 if not
 */
int hs_contains(HashSet *hs, void *element);

/*
 * returns 1 if hashset is empty, 0 if it is not
 */
int hs_isEmpty(HashSet *hs);

/*
 * removes the specified element from the set, if present
 *
 * if userFunction != NULL, invokes it on the element before removing it
 *
 * returns 1 if successful, 0 if not present
 */
int hs_remove(HashSet *hs, void *element, void (*userFunction)(void *));

/*
 * returns the number of elements in the hashset
 */
long hs_size(HashSet *hs);

/*
 * return the elements of the hashset as an array of void * pointers in an
 * arbitrary order
 *
 * returns pointer to the array or NULL if error
 * returns the number of elements in the array in `*len'
 */
void **hs_toArray(HashSet *hs, long *len);

#endif /* _HASHSET_H_ */
