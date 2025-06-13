r"""
This module provides functions for various interesting constructions of vector bundles.

AUTHORS:

_Mickaël Montessinos: initial implementation
"""

###########################################################################
#  Copyright (C) 2024 Mickaël Montessinos (mickael.montessinos@mif.vu.lt),#
#                                                                         #
#  Distributed under the terms of the GNU General Public License (GPL)    #
#  either version 3, or (at your option) any later version                #
#                                                                         #
#  http://www.gnu.org/licenses/                                           #
###########################################################################

from sage.matrix.constructor import matrix
from vector_bundle import VectorBundle
from . import function_field_utility

def trivial_bundle(K):
    r"""
    Return the structure sheaf of the algebraic curve with function field K.

    EXAMPLES ::

        sage: from vector_bundle import trivial_bundle
        sage: F.<x> = FunctionField(GF(3))
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y^2 + x + 2)
        sage: O = K.maximal_order()
        sage: V = trivial_bundle(K)
        sage: V._ideals
        [Ideal (1) of Maximal order of Function field in y defined by y^2 + x + 2]
        sage: V._g_finite
        [1]
        sage: V._g_infinite
        [1]
    """
    return VectorBundle(K, K.one().divisor())

def canonical_bundle(K):
    r"""
    Return a canonical line bundle over K suitable for explicit Serre duality.

    EXAMPLES ::

        sage: from vector_bundle import canonical_bundle, trivial_bundle
        sage: F.<x> = FunctionField(GF(3))
        sage: canonical_bundle(F).degree()
        -2
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y^2 - x^3 - x)
        sage: L = canonical_bundle(K); L
        Vector bundle of rank 1 over Function field in y defined by y^2 + 2*x^3 + 2*x
        sage: L == trivial_bundle(K)
        True
    """
    pi = function_field_utility.safe_uniformizers(K)[0]
    return VectorBundle(K, pi.differential().divisor())

def _euclid(a,b):
    r"""
    The Euclidian algorithm in `N` but outputs intermediate steps.
    """
    u1 = a
    u2 = b
    res = []
    while u2 != 0:
        q, r = u1.quo_rem(u2)
        res.append((u1, u2, q, r))
        u1 = u2
        u2 = r
    return res


def atiyah_bundle(field, rank, degree, base=None):
    r"""
    Return `\alpha_{r,d}(F_r \otimes base)` in the notation of Theorem 6 [At57]_
    , where `r` is ``rank`` and `d` is ``degree``.

    INPUT:

    - ``field`` - FunctionField; of genus 1 with an infinite place of degree 1
    - ``rank`` - integer
    - ``degree`` - integer
    - ``base`` - line bundle of degree 0 over field ; (default = ``trivial_bundle(field)``)

    EXAMPLES ::

        sage: from vector_bundle import atiyah_bundle
        sage: from vector_bundle import VectorBundle
        sage: F.<x> = FunctionField(GF(11))
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y^2 - x^3 - x)
        sage: base = VectorBundle(
        ....:       K,
        ....:       K.places_finite()[0].divisor()
        ....:       - K.places_infinite()[0].divisor())
        sage: E = atiyah_bundle(K, 5, 3, base)
        sage: E.rank()
        5
        sage: E.degree()
        3
        sage: E.hom(E).h0()
        [
        [1 0 0 0 0]
        [0 1 0 0 0]
        [0 0 1 0 0]
        [0 0 0 1 0]
        [0 0 0 0 1]
        ]
    """
    if base is None:
        base = trivial_bundle(field)
    if rank <= 0 :
        raise ValueError('rank must be positive')
    if field.genus() != 1:
        raise ValueError('field must have genus 1')
    if base.function_field() != field:
        raise ValueError('base must have field as its function_field.')
    if degree < 0:
        return atiyah_bundle(field, rank, -degree, base).dual()
    divisor = field.places_infinite()[0].divisor()
    if degree == 0:
        plan = []
        starting_rank = rank
    else:
        gcd = _euclid(rank, degree)
        plan = [(i % 2,q) for i,(_, _, q, _) in enumerate(gcd)]
        a, b = plan[-1]
        plan[-1] = (a, b - 1)
        starting_rank = gcd[-1][1]
    result = trivial_bundle(field)
    line_bundle = VectorBundle(field, divisor)
    for _ in range(starting_rank - 1):
        result = result.extension_by_global_sections()
    result = result.tensor_product(base)
    if degree > 0:
        result = result.tensor_product(line_bundle)
    for op, reps in reversed(plan):
        for _ in range(reps):
            if op:
                result = result.tensor_product(line_bundle)
            else:
                result = result.extension_by_global_sections()
    return result


def savin_bundle(field, rank, degree, line, line_1, line_2):
    r"""
    Return a weakly stable bundle over field of rank ``rank`` and degree
    ``degree``

    ALGORITHM:

    Section V of [Sav08]_

    INPUT:

    - ``field`` -- FunctionField: the base of the bundle. Must have genus at least 2.

    - ``rank`` -- Integer: the rank of the output bundle

    - ``degree`` -- Integer: the degree of the output bundle

    - ``line`` -- VectorBundle: line bundle of degree ``degree//rank + 1`` plays the role of `F` in the algorithm

    - ``line_1`` -- VectorBundle: line bundle of degree ``degree // rank`` plays the role of `F_1` in the algorithm

    - ``line_2`` -- VectorBundle: line bundle of degree ``degree // rank`` plays the role of `F_2` in the algorithm

    EXAMPLE ::

        sage: from vector_bundle import VectorBundle, savin_bundle
        sage: F.<x> = FunctionField(GF(11))
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y^2 - x^5 + x)
        sage: line = VectorBundle(K, 3 * K.places_infinite()[0].divisor())
        sage: line_1 = VectorBundle(K, 2 * K.places_finite()[0].divisor())
        sage: line_2 = VectorBundle(K, 2 * K.places_finite()[1].divisor())
        sage: E = savin_bundle(K, 3, 7, line, line_1, line_2)
        sage: E.rank()
        3
        sage: E.degree()
        7
    """
    if degree < 0:
        return savin_bundle(field, rank, -degree, line, line_1, line_2).dual()
    q, r = degree.quo_rem(rank)
    if line.rank() != 1 or line_1.rank() != 1 or line_2.rank() != 1:
        raise ValueError('The input bundles must have rank 1')
    if line_1.degree() != q or line_1.degree() != q or line.degree() != q+1:
        raise ValueError('At least one of the input line bundles has'
                         + 'invalid degree')
    E = line_1
    for _ in range(rank - r - 1):
        E = line_2.non_trivial_extension(E)
    for _ in range(r):
        E = line.non_trivial_extension(E)
    return E

def rank_2_trivial_determinant_semistable_bundle(ksi, ext=None):
    r"""
    Construct the semi-stable vector bundle of rank 2 and trivial determinant
    defined by the extension of ``ksi`` by ``ksi.dual()`` and nonzero extension
    class ``ext``.

    The fact that this vector bundle is semi-stable is Lemma 5.1 in [NR69]_.
    If ``ext`` is None, we default to a default nonzero extension class.

    INPUT:

    - ``ksi`` -- a degree 1 line bundle over a function field of genus at least 2
    - ``ext`` -- an object representing a class of extensions of ``ksi`` by ``ksi.dual()``. (Default: None)

    EXAMPLES ::

        sage: from vector_bundle import VectorBundle, trivial_bundle, rank_2_trivial_determinant_semistable_bundle
        sage: F.<x> = FunctionField(GF(11))
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y^2 - x^5 - 1)
        sage: ksi = VectorBundle(K, K.places_finite()[0].divisor())
        sage: V = rank_2_trivial_determinant_semistable_bundle(ksi)
        sage: V.rank()
        2
        sage: V.determinant() == trivial_bundle(K)
        True
    """
    if ksi.rank() != 1:
        raise ValueError('ksi must have rank one')
    if ksi.degree() != 1:
        raise ValueError('ksi must have degree one')
    if ksi.function_field().genus() < 2:
        raise ValueError('The function field of ksi must have genus at least 2')
    ext_group = ksi.extension_group(ksi.dual())
    return ext_group.extension(ext)
