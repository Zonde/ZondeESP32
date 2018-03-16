#include "unity.h"
#include "set.h"

TEST_CASE("discard duplicates", "[set]") {
    set* s = set_create(5, 2);
    TEST_ASSERT_FALSE(set_add(s, "hello"));
    TEST_ASSERT_TRUE(set_add(s, "hello"));
    TEST_ASSERT_FALSE(set_add(s, "world"));

}

