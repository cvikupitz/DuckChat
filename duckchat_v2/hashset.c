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

#include "hashset.h"
#include <stdlib.h>
#include <string.h>

#define DEFAULT_CAPACITY 16
#define MAX_CAPACITY 134217728L
#define DEFAULT_LOAD_FACTOR 0.75
#define TRIGGER 100	/* number of changes that will trigger a load check */

typedef struct entry {
    struct entry *next;
    void *element;
} Entry;

struct hashset {
    long size;
    long capacity;
    long changes;
    double load;
    double loadFactor;
    double increment;
    int (*cmp)(void *, void *);
    long (*hash)(void *, long);
    Entry **buckets;
};

HashSet *hs_create(int (*cmpFn)(void*,void*), long (*hashFn)(void*,long),
                   long capacity, double loadFactor) {
    HashSet *hs;
    long N;
    double lf;
    Entry **array;
    long i;

    hs = (HashSet *)malloc(sizeof(HashSet));
    if (hs != NULL) {
        N = ((capacity > 0) ? capacity : DEFAULT_CAPACITY);
        if (N > MAX_CAPACITY)
            N = MAX_CAPACITY;
        lf = ((loadFactor > 0.000001) ? loadFactor : DEFAULT_LOAD_FACTOR);
        array = (Entry **)malloc(N * sizeof(Entry *));
        if (array != NULL) {
            hs->capacity = N;
            hs->loadFactor = lf;
            hs->size = 0L;
            hs->load = 0.0;
            hs->changes = 0L;
            hs->increment = 1.0 / (double)N;
            hs->cmp = cmpFn;
            hs->hash = hashFn;
            hs->buckets = array;
            for (i = 0; i < N; i++)
                array[i] = NULL;
        } else {
            free(hs);
            hs = NULL;
        }
    }
    return hs;
}

/*
 * traverses the hashset, calling userFunction on each element
 * then frees storage associated with the key and the Entry structure
 */
static void purge(HashSet *hs, void (*userFunction)(void *element)) {

    long i;

    for (i = 0L; i < hs->capacity; i++) {
        Entry *p, *q;
        p = hs->buckets[i];
        while (p != NULL) {
            if (userFunction != NULL)
                (*userFunction)(p->element);
            q = p->next;
            free(p);
            p = q;
        }
        hs->buckets[i] = NULL;
    }
}

void hs_destroy(HashSet *hs, void (*userFunction)(void *element)) {
    purge(hs, userFunction);
    free(hs->buckets);
    free(hs);
}

void hs_clear(HashSet *hs, void (*userFunction)(void *element)) {
    purge(hs, userFunction);
    hs->size = 0;
    hs->load = 0.0;
    hs->changes = 0;
}

/*
 * local function to locate entry in a hashset
 *
 * returns pointer to entry, if found, as function value; NULL if not found
 * returns bucket index in `*bucket'
 */
static Entry *findEntry(HashSet *hs, void *element, long *bucket) {
    long i = hs->hash(element, hs->capacity);
    Entry *p;

    *bucket = i;
    for (p = hs->buckets[i]; p != NULL; p = p->next) {
        if (hs->cmp(p->element, element) == 0) {
            break;
        }
    }
    return p;
}

/*
 * local function that resizes the hashset
 */
static void resize(HashSet *hs) {
    int N;
    Entry *p, *q, **array;
    long i, j;

    N = 2 * hs->capacity;
    if (N > MAX_CAPACITY)
        N = MAX_CAPACITY;
    if (N == hs->capacity)
        return;
    array = (Entry **)malloc(N * sizeof(Entry *));
    if (array == NULL)
        return;
    for (j = 0; j < N; j++)
        array[j] = NULL;
    /*
     * now redistribute the entries into the new set of buckets
     */
    for (i = 0; i < hs->capacity; i++) {
        for (p = hs->buckets[i]; p != NULL; p = q) {
            q = p->next;
            j = hs->hash(p->element, N);
            p->next = array[j];
            array[j] = p;
        }
    }
    free(hs->buckets);
    hs->buckets = array;
    hs->capacity = N;
    hs->load /= 2.0;
    hs->changes = 0;
    hs->increment = 1.0 / (double)N;
}

int hs_add(HashSet *hs, void *element) {
    long i;
    Entry *p;
    int ans = 0;

    if (hs->changes > TRIGGER) {
        hs->changes = 0;
        if (hs->load > hs->loadFactor)
            resize(hs);
    }
    p = findEntry(hs, element, &i);
    if (p == NULL) {	/* element does not exist in set */
        p = (Entry *)malloc(sizeof(Entry));
        if (p != NULL) {
            p->element = element;
            p->next = hs->buckets[i];
            hs->buckets[i] = p;
            hs->size++;
            hs->load += hs->increment;
            hs->changes++;
            ans = 1;
        } else {
            free(p);
        }
    }
    return ans;
}

int hs_contains(HashSet *hs, void *element) {
    long bucket;

    return (findEntry(hs, element, &bucket) != NULL);
}

int hs_isEmpty(HashSet *hs) {
    return (hs->size == 0L);
}

int hs_remove(HashSet *hs, void *element, void (*userFunction)(void*)) {
    long i;
    Entry *entry;
    int ans = 0;

    entry = findEntry(hs, element, &i);
    if (entry != NULL) {
        Entry *p, *c;
        /* determine where the entry lives in the singly linked list */
        for (p = NULL, c = hs->buckets[i]; c != entry; p = c, c = c->next)
            ;
        if (p == NULL)
            hs->buckets[i] = entry->next;
        else
            p->next = entry->next;
        hs->size--;
        hs->load -= hs->increment;
        hs->changes++;
        if (userFunction != NULL)
            (*userFunction)(entry->element);
        free(entry);
        ans = 1;
    }
    return ans;
}

long hs_size(HashSet *hs) {
    return hs->size;
}

/*
 * local function for generating an array of void * from a hashset
 *
 * returns pointer to the array or NULL if malloc failure
 */
static void **entries(HashSet *hs) {
    void **tmp = NULL;
    if (hs->size > 0L) {
        size_t nbytes = hs->size * sizeof(void *);
        tmp = (void **)malloc(nbytes);
        if (tmp != NULL) {
            long i, n = 0L;
            for (i = 0L; i < hs->capacity; i++) {
                Entry *p;
                p = hs->buckets[i];
                while (p != NULL) {
                    tmp[n++] = p->element;
                    p = p->next;
                }
            }
        }
    }
    return tmp;
}

void **hs_toArray(HashSet *hs, long *len) {
    void **tmp = entries(hs);

    if (tmp != NULL)
        *len = hs->size;
    return tmp;
}
