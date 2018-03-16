#ifndef SET_H
#define SET_H

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct set set;

/* 
 * Create a new set
 * elem_size: Number of bytes per element
 * capacity: Number of elements that can fit before reallocating
 * 
 * Returns a handle to the new set
 *
 * N.B. Don't forget to destroy the set afterwards!
 */
set* set_create(size_t elem_size, size_t capacity);

/* Destroy the set */
void set_destroy(set* s);

/*
 * Add a new item to the set.
 *
 * Returns true if the item was already in the set.
 */
bool set_add(set* s, void* elem);

/* Returns true if the elements is in the set, false otherwise */
bool set_has_member(set* s, void* elem);

/* Returns the number of elements in the set */
size_t set_size(set* s);

/* Returns a pointer to the elements in the set */
void* set_items(set* s);

void* set_elem_at(set* s, size_t i);

void set_clear(set* s);

/*
 * Below macro generates a type-safe interface sets
 */

// Put this in the header file
#define SET_DEF(elem_type)                                                  \
typedef struct {                                                            \
    set* _set;                                                              \
} elem_type ## _set;                                                        \
elem_type ## _set elem_type ## _set_create(size_t capacity);                \
void elem_type ## _set_destroy(elem_type ## _set s);                        \
bool elem_type ## _set_add(elem_type ## _set s, elem_type *elem);           \
bool elem_type ## _set_has_member(elem_type ## _set s, elem_type *elem);    \
size_t elem_type ## _set_size(elem_type ## _set s);                         \
elem_type * elem_type ## _set_items(elem_type ## _set s);                   \
elem_type * elem_type ## _set_elem_at(elem_type ## _set s, size_t i);       \
void elem_type ## _set_clear(elem_type ## _set s);                          \

// Put this in the source file
#define SET_IMPL(elem_type)                                                 \
elem_type ## _set elem_type ## _set_create(size_t capacity) {               \
    elem_type ## _set s;                                                    \
    s._set = set_create(sizeof(elem_type), capacity);                       \
    return s;                                                               \
}                                                                           \
void elem_type ## _set_destroy(elem_type ## _set s) {                       \
    set_destroy(s._set);                                                    \
}                                                                           \
bool elem_type ## _set_add(elem_type ## _set s, elem_type *elem) {          \
    return set_add(s._set, elem);                                           \
}                                                                           \
bool elem_type ## _set_has_member(elem_type ## _set s, elem_type *elem) {   \
    return set_has_member(s._set, elem);                                    \
}                                                                           \
size_t elem_type ## _set_size(elem_type ## _set s) {                        \
    return set_size(s._set);                                                \
}                                                                           \
elem_type * elem_type ## _set_items(elem_type ## _set s) {                  \
    return (elem_type *) set_items(s._set);                                 \
}                                                                           \
elem_type * elem_type ## _set_elem_at(elem_type ## _set s, size_t i) {      \
    return (elem_type *) set_elem_at(s._set, i);                            \
}                                                                           \
void elem_type ## _set_clear(elem_type ## _set s) {                         \
    set_clear(s._set);                                                      \
}                                                                           \

#endif
