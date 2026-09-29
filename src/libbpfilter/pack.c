/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/pack.h"

#include <errno.h>

#include "bpfilter/core/list.h"
#include "bpfilter/helper.h"
#include "bpfilter/logger.h"
#include "mpack.h"

struct bf_wpack
{
    void *data;
    size_t data_len;
    size_t data_cap;

    char buffer[64];
    mpack_writer_t writer;
};

static void _bf_wpack_writer_flush_cb(mpack_writer_t *writer,
                                      const char *buffer, size_t count)
{
    bf_wpack_t *pack = writer->context;
    int r;

    if (pack->data_cap <= pack->data_len + count) {
        size_t new_cap = pack->data_cap ?: 64;

        while (new_cap <= pack->data_len + count)
            new_cap <<= 1;

        r = bf_realloc(&pack->data, new_cap);
        if (r) {
            mpack_writer_flag_error(writer, mpack_error_memory);
            return;
        }

        pack->data_cap = new_cap;
    }

    memcpy(pack->data + pack->data_len, buffer, count);
    pack->data_len += count;
}

int bf_wpack_new(bf_wpack_t **pack)
{
    bf_wpack_t *_pack = NULL;

    assert(pack);

    _pack = malloc(sizeof(*_pack));
    if (!_pack)
        return -ENOMEM;

    _pack->data = NULL;
    _pack->data_cap = 0;
    _pack->data_len = 0;

    mpack_writer_init(&_pack->writer, _pack->buffer, 64);

    /* Use a custom flush function so we can control the flush
     * (e.g. when get_data() is called). */
    mpack_writer_set_flush(&_pack->writer, _bf_wpack_writer_flush_cb);
    mpack_writer_set_context(&_pack->writer, _pack);

    mpack_build_map(&_pack->writer);

    *pack = TAKE_PTR(_pack);

    return 0;
}

void bf_wpack_free(bf_wpack_t **pack)
{
    bf_wpack_t *_pack;

    assert(pack);

    _pack = *pack;
    if (!_pack)
        return;

    mpack_writer_destroy(&_pack->writer);

    BF_FREEP(&_pack->data);
    BF_FREEP(pack);
}

bool bf_wpack_is_valid(bf_wpack_t *pack)
{
    mpack_error_t error;

    assert(pack);

    error = mpack_writer_error(&pack->writer);
    if (error != mpack_ok)
        return false;

    return true;
}

int bf_wpack_get_data(bf_wpack_t *pack, const void **data, size_t *data_len)
{
    assert(pack);
    assert(data);
    assert(data_len);

    mpack_complete_map(&pack->writer);

    mpack_writer_flush_message(&pack->writer);
    if (!bf_wpack_is_valid(pack))
        return -EINVAL;

    *data_len = pack->data_len;
    *data = pack->data;

    return 0;
}

void bf_wpack_nil(bf_wpack_t *pack)
{
    mpack_write_nil(&pack->writer);
}

void bf_wpack_int(bf_wpack_t *pack, int value)
{
    mpack_write_int(&pack->writer, value);
}

void bf_wpack_uint(bf_wpack_t *pack, unsigned int value)
{
    mpack_write_uint(&pack->writer, value);
}

void bf_wpack_u8(bf_wpack_t *pack, uint8_t value)
{
    mpack_write_u8(&pack->writer, value);
}

void bf_wpack_u16(bf_wpack_t *pack, uint16_t value)
{
    mpack_write_u16(&pack->writer, value);
}

void bf_wpack_u32(bf_wpack_t *pack, uint32_t value)
{
    mpack_write_u32(&pack->writer, value);
}

void bf_wpack_u64(bf_wpack_t *pack, uint64_t value)
{
    mpack_write_u64(&pack->writer, value);
}

void bf_wpack_bool(bf_wpack_t *pack, bool value)
{
    mpack_write_bool(&pack->writer, value);
}

void bf_wpack_str(bf_wpack_t *pack, const char *value)
{
    mpack_write_cstr(&pack->writer, value);
}

void bf_wpack_bin(bf_wpack_t *pack, const void *value, size_t len)
{
    assert(pack);
    assert(value);

    mpack_write_bin(&pack->writer, value, len);
}

void bf_wpack_list(bf_wpack_t *pack, const bf_list *value)
{
    int r;

    assert(pack);
    assert(value);

    bf_wpack_open_array(pack, NULL);
    r = bf_list_pack(value, pack);
    if (r)
        mpack_writer_flag_error(&pack->writer, mpack_error_invalid);
    bf_wpack_close_array(pack);
}

void bf_wpack_kv_list(bf_wpack_t *pack, const char *key, const bf_list *value)
{
    bf_wpack_str(pack, key);
    bf_wpack_list(pack, value);
}

void bf_wpack_open_object(bf_wpack_t *pack, const char *key)
{
    assert(pack);

    if (key)
        mpack_write_cstr(&pack->writer, key);

    mpack_build_map(&pack->writer);
}

void bf_wpack_close_object(bf_wpack_t *pack)
{
    assert(pack);

    mpack_complete_map(&pack->writer);
}

void bf_wpack_open_array(bf_wpack_t *pack, const char *key)
{
    assert(pack);

    if (key)
        mpack_write_cstr(&pack->writer, key);

    mpack_build_array(&pack->writer);
}

void bf_wpack_close_array(bf_wpack_t *pack)
{
    assert(pack);

    mpack_complete_array(&pack->writer);
}

struct bf_rpack
{
    const void *data;
    size_t data_len;

    mpack_tree_t tree;
    mpack_node_t root;
};

int bf_rpack_new(bf_rpack_t **pack, const void *data, size_t data_len)
{
    _free_bf_rpack_ bf_rpack_t *_pack = NULL;
    mpack_error_t error;

    assert(pack);

    _pack = calloc(1, sizeof(*_pack));
    if (!_pack)
        return -ENOMEM;

    _pack->data = data;
    _pack->data_len = data_len;

    mpack_tree_init_data(&_pack->tree, data, data_len);

    mpack_tree_parse(&_pack->tree);
    error = mpack_tree_error(&_pack->tree);
    if (error != mpack_ok) {
        return bf_err_r(-EINVAL, "failed to parse bf_rpack_t data: %s",
                        mpack_error_to_string(error));
    }

    _pack->root = mpack_tree_root(&_pack->tree);

    *pack = TAKE_PTR(_pack);

    return 0;
}

void bf_rpack_free(bf_rpack_t **pack)
{
    bf_rpack_t *_pack;

    assert(pack);

    _pack = *pack;
    if (!_pack)
        return;

    mpack_tree_destroy(&_pack->tree);
    BF_FREEP(pack);
}

#define MP_NODE(node) (*(mpack_node_t *)&(node))
#define BF_NODE(node)                                                          \
    ({                                                                         \
        union                                                                  \
        {                                                                      \
            mpack_node_t m;                                                    \
            bf_rpack_node_t b;                                                 \
        } _u_ = {0};                                                           \
        _u_.m = (node);                                                        \
        _u_.b;                                                                 \
    })

static_assert(sizeof(bf_rpack_node_t) >= sizeof(mpack_node_t),
              "bf_rpack_node_t too small for mpack_node_t");

bf_rpack_node_t bf_rpack_root(const bf_rpack_t *pack)
{
    return BF_NODE(pack->root);
}

size_t bf_rpack_array_count(bf_rpack_node_t node)
{
    return mpack_node_array_length(MP_NODE(node));
}

bool bf_rpack_is_nil(bf_rpack_node_t node)
{
    if (mpack_node_error(MP_NODE(node)) != mpack_ok)
        return false;

    return mpack_node_type(MP_NODE(node)) == mpack_type_nil;
}

bool bf_rpack_is_array(bf_rpack_node_t node)
{
    if (mpack_node_error(MP_NODE(node)) != mpack_ok)
        return false;

    return mpack_node_type(MP_NODE(node)) == mpack_type_array;
}

bf_rpack_node_t bf_rpack_array_value_at(bf_rpack_node_t node, size_t index)
{
    return BF_NODE(mpack_node_array_at(MP_NODE(node), index));
}

bool bf_rpack_kv_contains(bf_rpack_node_t node, const char *key)
{
    return mpack_node_map_contains_cstr(MP_NODE(node), key);
}

int bf_rpack_kv_node(bf_rpack_node_t node, const char *key,
                     bf_rpack_node_t *child)
{
    mpack_node_t _node = MP_NODE(node);

    assert(key);
    assert(child);

    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    if (mpack_node_type(_node) != mpack_type_map)
        return -EDOM;

    if (!mpack_node_map_contains_cstr(_node, key))
        return -ENOENT;

    *child = BF_NODE(mpack_node_map_cstr(_node, key));

    return 0;
}

int bf_rpack_int(bf_rpack_node_t node, int *value)
{
    mpack_node_t _node = MP_NODE(node);
    int _value;

    /* Signed integere are sometimes stored as unsigned integer for optimization
     * purposes. While not ideal, we should allow the node to be an unsigned
     * integer. */
    if (mpack_node_type(_node) != mpack_type_int &&
        mpack_node_type(_node) != mpack_type_uint)
        return -EDOM;

    _value = mpack_node_int(_node);
    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    *value = _value;

    return 0;
}

int bf_rpack_kv_int(bf_rpack_node_t node, const char *key, int *value)
{
    bf_rpack_node_t child;
    int r;

    r = bf_rpack_kv_node(node, key, &child);
    if (r)
        return r;

    return bf_rpack_int(child, value);
}

int bf_rpack_uint(bf_rpack_node_t node, unsigned int *value)
{
    mpack_node_t _node = MP_NODE(node);
    unsigned int _value;

    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    if (mpack_node_type(_node) != mpack_type_uint)
        return -EDOM;

    _value = mpack_node_uint(_node);
    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    *value = _value;

    return 0;
}

int bf_rpack_kv_uint(bf_rpack_node_t node, const char *key, unsigned int *value)
{
    bf_rpack_node_t child;
    int r;

    r = bf_rpack_kv_node(node, key, &child);
    if (r)
        return r;

    return bf_rpack_uint(child, value);
}

int bf_rpack_u8(bf_rpack_node_t node, uint8_t *value)
{
    mpack_node_t _node = MP_NODE(node);
    uint8_t _value;

    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    if (mpack_node_type(_node) != mpack_type_uint)
        return -EDOM;

    _value = mpack_node_u8(_node);
    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    *value = _value;

    return 0;
}

int bf_rpack_kv_u8(bf_rpack_node_t node, const char *key, uint8_t *value)
{
    bf_rpack_node_t child;
    int r;

    r = bf_rpack_kv_node(node, key, &child);
    if (r)
        return r;

    return bf_rpack_u8(child, value);
}

int bf_rpack_u16(bf_rpack_node_t node, uint16_t *value)
{
    mpack_node_t _node = MP_NODE(node);
    uint16_t _value;

    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    if (mpack_node_type(_node) != mpack_type_uint)
        return -EDOM;

    _value = mpack_node_u16(_node);
    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    *value = _value;

    return 0;
}

int bf_rpack_kv_u16(bf_rpack_node_t node, const char *key, uint16_t *value)
{
    bf_rpack_node_t child;
    int r;

    r = bf_rpack_kv_node(node, key, &child);
    if (r)
        return r;

    return bf_rpack_u16(child, value);
}

int bf_rpack_u32(bf_rpack_node_t node, uint32_t *value)
{
    mpack_node_t _node = MP_NODE(node);
    uint32_t _value;

    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    if (mpack_node_type(_node) != mpack_type_uint)
        return -EDOM;

    _value = mpack_node_u32(_node);
    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    *value = _value;

    return 0;
}

int bf_rpack_kv_u32(bf_rpack_node_t node, const char *key, uint32_t *value)
{
    bf_rpack_node_t child;
    int r;

    r = bf_rpack_kv_node(node, key, &child);
    if (r)
        return r;

    return bf_rpack_u32(child, value);
}

int bf_rpack_u64(bf_rpack_node_t node, uint64_t *value)
{
    mpack_node_t _node = MP_NODE(node);
    uint64_t _value;

    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    if (mpack_node_type(_node) != mpack_type_uint)
        return -EDOM;

    _value = mpack_node_u64(_node);
    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    *value = _value;

    return 0;
}

int bf_rpack_size(bf_rpack_node_t node, size_t *value)
{
    uint64_t _value;
    int r;

    r = bf_rpack_u64(node, &_value);
    if (r)
        return r;

#if SIZE_MAX < UINT64_MAX
    if (_value > SIZE_MAX)
        return -EOVERFLOW;
#endif

    *value = _value;

    return 0;
}

int bf_rpack_kv_u64(bf_rpack_node_t node, const char *key, uint64_t *value)
{
    bf_rpack_node_t child;
    int r;

    r = bf_rpack_kv_node(node, key, &child);
    if (r)
        return r;

    return bf_rpack_u64(child, value);
}

int bf_rpack_kv_size(bf_rpack_node_t node, const char *key, size_t *value)
{
    bf_rpack_node_t child;
    int r;

    r = bf_rpack_kv_node(node, key, &child);
    if (r)
        return r;

    return bf_rpack_size(child, value);
}

int bf_rpack_str(bf_rpack_node_t node, char **value)
{
    mpack_node_t _node = MP_NODE(node);
    _cleanup_free_ char *_value = NULL;

    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    if (mpack_node_type(_node) != mpack_type_str)
        return -EDOM;

    _value = mpack_node_cstr_alloc(_node, mpack_node_strlen(_node) + 1);
    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    *value = TAKE_PTR(_value);

    return 0;
}

int bf_rpack_kv_str(bf_rpack_node_t node, const char *key, char **value)
{
    bf_rpack_node_t child;
    int r;

    assert(key);
    assert(value);

    r = bf_rpack_kv_node(node, key, &child);
    if (r)
        return r;

    return bf_rpack_str(child, value);
}

int bf_rpack_bool(bf_rpack_node_t node, bool *value)
{
    mpack_node_t _node = MP_NODE(node);
    bool _value;

    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    if (mpack_node_type(_node) != mpack_type_bool)
        return -EDOM;

    _value = mpack_node_bool(_node);
    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    *value = _value;

    return 0;
}

int bf_rpack_kv_bool(bf_rpack_node_t node, const char *key, bool *value)
{
    bf_rpack_node_t child;
    int r;

    r = bf_rpack_kv_node(node, key, &child);
    if (r)
        return r;

    return bf_rpack_bool(child, value);
}

int bf_rpack_bin(bf_rpack_node_t node, const void **data, size_t *data_len)
{
    mpack_node_t _node = MP_NODE(node);
    const void *_data;
    size_t _data_len;

    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    if (mpack_node_type(_node) != mpack_type_bin)
        return -EDOM;

    _data_len = mpack_node_bin_size(_node);
    _data = mpack_node_bin_data(_node);
    if (mpack_node_error(_node) != mpack_ok)
        return -EINVAL;

    *data = _data;
    *data_len = _data_len;

    return 0;
}

int bf_rpack_kv_bin(bf_rpack_node_t node, const char *key, const void **data,
                    size_t *data_len)
{
    bf_rpack_node_t child;
    int r;

    r = bf_rpack_kv_node(node, key, &child);
    if (r)
        return r;

    return bf_rpack_bin(child, data, data_len);
}

int bf_rpack_kv_obj(bf_rpack_node_t node, const char *key,
                    bf_rpack_node_t *child)
{
    bf_rpack_node_t _child;
    int r;

    assert(key);
    assert(child);

    r = bf_rpack_kv_node(node, key, &_child);
    if (r)
        return r;

    if (mpack_node_type(MP_NODE(_child)) != mpack_type_map)
        return -EDOM;

    *child = _child;

    return 0;
}

int bf_rpack_kv_array(bf_rpack_node_t node, const char *key,
                      bf_rpack_node_t *child)
{
    bf_rpack_node_t _child;
    int r;

    assert(key);
    assert(child);

    r = bf_rpack_kv_node(node, key, &_child);
    if (r)
        return r;

    if (mpack_node_type(MP_NODE(_child)) != mpack_type_array)
        return -EDOM;

    *child = _child;

    return 0;
}
