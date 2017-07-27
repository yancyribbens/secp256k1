/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra, Peter Dettmann                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include "ecmult_multi.h"

typedef struct {
    uint32_t tree[SECP256K1_ECMULT_MULTI_MAX_N];
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

static void secp256k1_heap_initialize(secp256k1_scalar_heap *heap, const secp256k1_scalar *scalars, const secp256k1_gej *pt, size_t n) {
    size_t i, size = 0;

    VERIFY_CHECK(n <= SECP256K1_ECMULT_MULTI_MAX_N);

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
static void secp256k1_ecmult_multi_bos_coster(secp256k1_gej *r, secp256k1_scalar *sc, secp256k1_gej *pt, size_t n) {
    secp256k1_scalar_heap heap;
    uint32_t first, second;

    secp256k1_gej_set_infinity(r);
    secp256k1_heap_initialize(&heap, sc, pt, n);

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
    secp256k1_gej tmp;
    secp256k1_gej pt[SECP256K1_ECMULT_MULTI_MAX_N + 1];  /* +1 in case we spill over doing the endomorphism 2 points at a time */
    secp256k1_scalar sc[SECP256K1_ECMULT_MULTI_MAX_N + 1];
    size_t idx = 0;
    size_t point_idx = 0;

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
#endif
        if (idx >= SECP256K1_ECMULT_MULTI_MAX_N) {
            secp256k1_ecmult_multi_bos_coster(&tmp, sc, pt, idx);
            secp256k1_gej_add_var(r, r, &tmp, NULL);
            idx = 0;
        }
        point_idx++;
    }
    secp256k1_ecmult_multi_bos_coster(&tmp, sc, pt, idx);
    secp256k1_gej_add_var(r, r, &tmp, NULL);
    return 1;
}

