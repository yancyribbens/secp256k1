/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra, Peter Dettmann                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include "ecmult_multi.h"

typedef struct {
    uint32_t *tree;
    const secp256k1_scalar *scalars;
    size_t size;
} secp256k1_scalar_heap;

static void secp256k1_sift_down(secp256k1_scalar_heap *heap, size_t node, uint32_t index) {
    uint32_t child_index, other_index;
    size_t child, other, half_size = heap->size >> 1;
    const secp256k1_scalar *sc = heap->scalars;

    while (node < half_size) {
        /* Initially assume the left child is the larger child */
        child = (node << 1) + 1;
        child_index = heap->tree[child];

        /* If there is a right child, check whether it's larger than the left */
        other = child + 1;
        if (other < heap->size) {
            other_index = heap->tree[other];
            if (secp256k1_scalar_cmp_var(&sc[other_index], &sc[child_index]) > 0) {
                child = other;
                child_index = other_index;
            }
        }

        /* If the current node is larger than its largest child, stop at this level */
        if (secp256k1_scalar_cmp_var(&sc[index], &sc[child_index]) > 0) {
            break;
        }

        /* Move the larger child up, and recurse from its previous position */
        heap->tree[node] = child_index;
        node = child;
    }

    heap->tree[node] = index;
}

static void secp256k1_sift_up(secp256k1_scalar_heap *heap, size_t node, uint32_t index) {
    size_t parent;
    uint32_t parent_index;
    const secp256k1_scalar *sc = heap->scalars;

    while (node > 0) {
        parent = (node - 1) >> 1;
        parent_index = heap->tree[parent];

        /* If the current node is not larger than its parent, stop at this level */
        if (secp256k1_scalar_cmp_var(&sc[index], &sc[parent_index]) <= 0) {
            break;
        }

        /* Move the parent down, and recurse from its previous position */
        heap->tree[node] = parent_index;
        node = parent;
    }

    heap->tree[node] = index;
}

static void secp256k1_sift_floyd(secp256k1_scalar_heap *heap, size_t node, uint32_t index) {
    uint32_t child_index, other_index;
    size_t child, other, half_size = heap->size >> 1;
    const secp256k1_scalar *sc = heap->scalars;

    while (node < half_size) {
        /* Initially assume the left child is the larger child */
        child = (node << 1) + 1;
        child_index = heap->tree[child];

        /* If there is a right child, check whether it's larger than the left */
        other = child + 1;
        if (other < heap->size) {
            other_index = heap->tree[other];
            if (secp256k1_scalar_cmp_var(&sc[other_index], &sc[child_index]) > 0) {
                child = other;
                child_index = other_index;
            }
        }

        /* Move the larger child up, and recurse from its previous position */
        heap->tree[node] = child_index;
        node = child;
    }

    secp256k1_sift_up(heap, node, index);
}

SECP256K1_INLINE static void secp256k1_heapify(secp256k1_scalar_heap *heap) {
    size_t root = heap->size >> 1;;
    while (root-- > 0) {
        secp256k1_sift_down(heap, root, heap->tree[root]);
    }
}

static void secp256k1_heap_initialize(secp256k1_scalar_heap *heap, uint32_t *tree, const secp256k1_scalar *scalars, const secp256k1_gej *pt, size_t n) {
    size_t i, size = 0;

    heap->tree = tree;
    for (i = 0; i < n; ++i) {
        if (!secp256k1_scalar_is_zero(&scalars[i]) && !secp256k1_gej_is_infinity(&pt[i])) {
            heap->tree[size++] = i;
        }
    }

    heap->scalars = scalars;
    heap->size = size;

    secp256k1_heapify(heap);
}

SECP256K1_INLINE static uint32_t secp256k1_replace(secp256k1_scalar_heap *heap, uint32_t index) {
    uint32_t result = heap->tree[0];
    VERIFY_CHECK(heap->size > 0);
    secp256k1_sift_floyd(heap, 0, index);
    return result;
}

SECP256K1_INLINE static uint32_t secp256k1_heap_remove(secp256k1_scalar_heap *heap) {
    uint32_t result = heap->tree[0];
    VERIFY_CHECK(heap->size > 0);
    if (--heap->size > 0) {
        secp256k1_sift_down(heap, 0, heap->tree[heap->size]);
    }
    return result;
}

/** Multi-multiply: R = sum_i ni * Ai */
static void secp256k1_ecmult_multi_bos_coster(uint32_t *tree_space, secp256k1_gej *r, secp256k1_scalar *sc, secp256k1_gej *pt, size_t n) {
    secp256k1_scalar_heap heap;
    uint32_t first, second;

    secp256k1_gej_set_infinity(r);
    secp256k1_heap_initialize(&heap, tree_space, sc, pt, n);

    if (heap.size == 0) {
        return;
    }

    first = secp256k1_heap_remove(&heap);

    while (heap.size > 0) {
        second = heap.tree[0];        

        do {
            /* Observe that nX + mY = (n-m)X + m(X + Y), and if n > m this transformation
             * reduces the magnitude of the larger scalar, on average by half. So by
             * repeating this we will quickly zero out all but one exponent, which will
             * be small. */
            secp256k1_gej_add_var(&pt[second], &pt[first], &pt[second], NULL);  /* Y -> X + Y */
            secp256k1_scalar_numsub(&sc[first], &sc[first], &sc[second]);  /* n -> n - m */

            if (secp256k1_scalar_cmp_var(&sc[first], &sc[second]) < 0) {
                break;
            }

            /* To handle pathological inputs, we use a binary ladder step here */
            if (secp256k1_scalar_shr_int(&sc[first], 1) == 1) {
                secp256k1_gej_add_var(r, r, &pt[first], NULL);
            }
            secp256k1_gej_double_var(&pt[first], &pt[first], NULL);
        }
        while (secp256k1_scalar_cmp_var(&sc[first], &sc[second]) >= 0);

        if (secp256k1_scalar_is_zero(&sc[first])) {
            first = secp256k1_heap_remove(&heap);
        } else {
            first = secp256k1_replace(&heap, first);
        }
    }

    VERIFY_CHECK(!secp256k1_scalar_is_zero(&sc[first]));

    /* Now the desired result is heap_sc[0] * heap_pt[0], and for random scalars it is
     * very likely that heap_sc[0] = 1, and extremely likely heap_sc[0] < 5. (After
     * about 100k trials I saw around 200 2's and one 3.) So use a binary ladder rather
     * than any heavy machinery to finish it off. */
    for (;;) {
        if (secp256k1_scalar_shr_int(&sc[first], 1) == 1) {
            secp256k1_gej_add_var(r, r, &pt[first], NULL);
            if (secp256k1_scalar_is_zero(&sc[first])) {
                break;
            }
        }
        secp256k1_gej_double_var(&pt[first], &pt[first], NULL);
    }
}

struct secp256k1_ecmult_point_state {
    int wnaf_na[256];
    int bits_na;
    size_t input_pos;
};

static void secp256k1_ecmult_multi_pippenger(secp256k1_gej *r, secp256k1_scalar *sc, secp256k1_gej *pt, size_t num) {
    struct secp256k1_ecmult_point_state state[SECP256K1_ECMULT_MULTI_MAX_N];
    int bits = 0;
    size_t np;
    size_t no = 0;
    int i;
    int j;
    int idx;
    secp256k1_gej running_sum;
    secp256k1_gej tmp;
    secp256k1_gej buckets_pos[ECMULT_TABLE_SIZE(WINDOW_A)];
    secp256k1_gej buckets_neg[ECMULT_TABLE_SIZE(WINDOW_A)];
    int n;
    for (np = 0; np < num; ++np) {
        if (secp256k1_scalar_is_zero(&sc[np]) || secp256k1_gej_is_infinity(&pt[np])) {
            continue;
        }
        state[no].input_pos = np;
        state[no].bits_na = secp256k1_ecmult_wnaf(state[no].wnaf_na,     256, &sc[np],      WINDOW_A);
        if (state[no].bits_na > bits) {
            bits = state[no].bits_na;
        }
        no++;
    }

    secp256k1_gej_set_infinity(r);
    for (i = bits - 1; i >= 0; i--) {
        for(j = 0; j < ECMULT_TABLE_SIZE(WINDOW_A); j++) {
            secp256k1_gej_set_infinity(&buckets_pos[j]);
            secp256k1_gej_set_infinity(&buckets_neg[j]);
        }
        secp256k1_gej_double_var(r, r, NULL);

        for (np = 0; np < no; ++np) {
            if (i < state[np].bits_na && (n = state[np].wnaf_na[i])) {
                /* printf("n: %d, ecmult_table_size %d\n", n, ECMULT_TABLE_SIZE(WINDOW_A)); */
                if (n > 0) {
                    idx = (n - 1)/2;
                    secp256k1_gej_add_var(&buckets_pos[idx], &buckets_pos[idx], &pt[state[np].input_pos], NULL);
                } else {
                    idx = -(n + 1)/2;
                    secp256k1_gej_add_var(&buckets_neg[idx], &buckets_neg[idx], &pt[state[np].input_pos], NULL);
                }
            }
        }
        secp256k1_gej_set_infinity(&running_sum);
        for(j = ECMULT_TABLE_SIZE(WINDOW_A) - 1; j >= 0; j--) {
            secp256k1_gej_add_var(r, r, &running_sum, NULL);

            secp256k1_gej_add_var(&running_sum, &running_sum, &buckets_pos[j], NULL);
            secp256k1_gej_neg(&tmp, &buckets_neg[j]);
            secp256k1_gej_add_var(&running_sum, &running_sum, &tmp, NULL);

            secp256k1_gej_add_var(r, r, &running_sum, NULL);
        }
    }
}

#ifdef USE_ENDOMORPHISM
SECP256K1_INLINE static void secp256k1_ecmult_endo_split(secp256k1_scalar *s1, secp256k1_scalar *s2, secp256k1_gej *p1, secp256k1_gej *p2) {
    secp256k1_scalar tmp = *s1;
    secp256k1_scalar_split_lambda(s1, s2, &tmp);
    secp256k1_gej_mul_lambda(p2, p1);

    if (secp256k1_scalar_is_high(s1)) {
        secp256k1_scalar_negate(s1, s1);
        secp256k1_gej_neg(p1, p1);
    }
    if (secp256k1_scalar_is_high(s2)) {
        secp256k1_scalar_negate(s2, s2);
        secp256k1_gej_neg(p2, p2);
    }
}
#endif

static int secp256k1_ecmult_multi(secp256k1_scratch *scratch, const secp256k1_callback* error_callback, secp256k1_gej *r, const secp256k1_scalar *inp_g_sc, secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n) {
    const size_t entry_size = sizeof(secp256k1_gej) + sizeof(secp256k1_scalar) + sizeof(size_t);
    const size_t max_entries = secp256k1_scratch_max_allocation(scratch) / entry_size;
    /* Use 2(n+1) with the endomorphism, n+1 without, when calculating batch sizes.
     * The reason for +1 is that Bos-Coster requires we add the G scalar to the list of
     * other scalars. */
#ifdef USE_ENDOMORPHISM
    const size_t n_batches = (2*n + max_entries + 1) / max_entries;
    size_t entries_per_batch = (2*n + n_batches + 1) / n_batches;
#else
    const size_t n_batches = (n + max_entries) / max_entries;
    size_t entries_per_batch = (n + n_batches) / n_batches;
#endif

    secp256k1_gej tmp;
    secp256k1_gej *pt;
    secp256k1_scalar *sc;
    uint32_t *tree_space;
    size_t idx = 0;
    size_t point_idx = 0;

    /* Attempt to allocate sufficient space for Bos-Coster */
    while (!secp256k1_scratch_resize(scratch, error_callback, entries_per_batch * entry_size)) {
        entries_per_batch /= 2;
        if (entries_per_batch < 2) {
            return 0;
        }
    }
    secp256k1_scratch_reset(scratch);
    pt = (secp256k1_gej *) secp256k1_scratch_alloc(scratch, entries_per_batch * sizeof(*pt));
    sc = (secp256k1_scalar *) secp256k1_scratch_alloc(scratch, entries_per_batch * sizeof(*sc));
    tree_space = (uint32_t *) secp256k1_scratch_alloc(scratch, entries_per_batch * sizeof(*tree_space));
    VERIFY_CHECK(pt != NULL);
    VERIFY_CHECK(sc != NULL);
    VERIFY_CHECK(tree_space != NULL);

    sc[0] = *inp_g_sc;
    secp256k1_gej_set_ge(&pt[0], &secp256k1_ge_const_g);
    idx++;
#ifdef USE_ENDOMORPHISM
    secp256k1_ecmult_endo_split(&sc[0], &sc[1], &pt[0], &pt[1]);
    idx++;
#endif

    secp256k1_gej_set_infinity(r);
    while (point_idx < n) {
        if (!cb(&sc[idx], &pt[idx], point_idx, cbdata)) {
            return 0;
        }
        idx++;
#ifdef USE_ENDOMORPHISM
        secp256k1_ecmult_endo_split(&sc[idx - 1], &sc[idx], &pt[idx - 1], &pt[idx]);
        idx++;
        if (idx >= entries_per_batch - 1) {
#else
        if (idx >= entries_per_batch) {
#endif
            secp256k1_ecmult_multi_pippenger(&tmp, sc, pt, idx);
            secp256k1_gej_add_var(r, r, &tmp, NULL);
            idx = 0;
        }
        point_idx++;
    }
    secp256k1_ecmult_multi_pippenger(&tmp, sc, pt, idx);
    secp256k1_gej_add_var(r, r, &tmp, NULL);
    return 1;
}

