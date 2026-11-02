from avci.normalize import (
    dedupe_key,
    is_static_path,
    normalize_path,
    query_param_keys,
)


def test_numeric_segment_normalized():
    assert normalize_path("/post/123") == "/post/{id}"
    assert normalize_path("/post/123/comments/9") == "/post/{id}/comments/{id}"


def test_uuid_and_long_hex_normalized():
    assert normalize_path("/u/550e8400-e29b-41d4-a716-446655440000") == "/u/{id}"
    assert normalize_path("/doc/507f1f77bcf86cd799439011") == "/doc/{id}"


def test_normal_segments_untouched():
    assert normalize_path("/api/users/me") == "/api/users/me"
    assert normalize_path("/") == "/"


def test_static_filter():
    assert is_static_path("/app/main.js")
    assert is_static_path("/a/b/style.CSS")
    assert is_static_path("/img/logo.png?v=2")
    assert not is_static_path("/api/users")
    assert not is_static_path("/api/v1.2/users")  # not an extension, a path segment
    assert not is_static_path("/post/123")


def test_query_keys_sorted_values_dropped():
    assert query_param_keys("b=2&a=1&a=3") == "a,b"
    assert query_param_keys("") == ""


def test_dedupe_key_stable():
    k1 = dedupe_key("get", "EXAMPLE.com", "/post/{id}", "a")
    k2 = dedupe_key("GET", "example.com", "/post/{id}", "a")
    assert k1 == k2
