#include "set.h"
#include "esp_log.h"

struct set {
    size_t elem_size;
    // Capacity and size in number of elements
    size_t capacity;
    size_t size;
    void* data;
};

set* set_create(size_t elem_size, size_t capacity) {
    if(capacity == 0) capacity = 1;
    set* s = malloc(sizeof(set));
    s->elem_size = elem_size;
    s->capacity = capacity;
    s->size = 0;
    s->data = calloc(capacity, elem_size);;
    return s;
}

void set_destroy(set* s) {
    free(s->data);
    free(s);
}

bool set_add(set* s, void* elem) {
    if(set_has_member(s, elem)) return true;
    if(s->capacity <= s->size) {
        // Double capacity
        size_t cap = s->capacity * 2;
        s->data = realloc(s->data, cap * s->elem_size);
        s->capacity = cap;
    }
    memcpy(set_elem_at(s, s->size), elem, s->elem_size);
    s->size++;
    return false;
}

bool set_has_member(set* s, void* elem) {
    for(size_t i = 0; i < s->size; i++) {
        if(memcmp(set_elem_at(s, i), elem, s->elem_size) == 0) {
            return true;
        }
    }
    return false;
}

size_t set_size(set* s) {
    return s-> size;
}

void* set_items(set* s) {
    return s->data;
}

void* set_elem_at(set* s, size_t i) {
    return (s->data) + (s->elem_size * i);
}

void set_clear(set* s) {
    s->size = 0;
}
