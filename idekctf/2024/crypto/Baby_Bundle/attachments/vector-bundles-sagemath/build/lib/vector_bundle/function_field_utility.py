r"""
    Implementations of all sort of algorithms for function field that are not 
    yet implemented in Sage.

    A lot of code for the FunctionFieldCompletionCustom class comes directly
    from the sage source, and was written by Kwankyu Lee.

    REFERENCE:
.. [Coh00] H. Cohen
   Advanced topics in computational number theory
   Springer
   2000
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
from sage.categories.map import Map
from sage.modules.free_module_element import vector
from sage.rings.infinity import infinity
from copy import copy
from sage.misc.cachefunc import cached_function
from sage.misc.misc_c import prod
from sage.matrix.constructor import matrix
from sage.matrix.special import block_matrix, elementary_matrix,\
        identity_matrix
from sage.rings.function_field.function_field_rational\
        import RationalFunctionField
from sage.rings.function_field.order_rational\
        import FunctionFieldMaximalOrderInfinite_rational
from sage.rings.function_field.order import FunctionFieldOrderInfinite
from sage.rings.function_field.ideal import FunctionFieldIdealInfinite

@cached_function
def all_infinite_places(K):
    r"""
    Return a list of the infinite places of K of all degrees

    INPUT:
        - ``K`` -- FunctionField
    """
    if isinstance(K,RationalFunctionField):
        return [K.gen().poles()[0]]
    deg = K.degree()
    return sum([K.places_infinite(degree = deg) for deg in range(1, deg + 1)],
               [])
    

def infinite_valuation(a):
    r"""
    Returns the valuation -deg of an element of a rational function field

    The degree method returns the "height" of the element.

    EXAMPLES:

        sage: from vector_bundle.function_field_utility import infinite_valuation
        sage: F.<x> = FunctionField(GF(3))
        sage: infinite_valuation(x**-1 + x**-2)
        1
    """
    if a == 0:
        return infinity
    return a.denominator().degree() - a.numerator().degree()


def infinite_mod(a,i):
    r"""
    Returns a mod x**-i

    EXAMPLES:

        sage: from vector_bundle.function_field_utility import infinite_mod
        sage: K.<x> = FunctionField(GF(3))
        sage: infinite_mod(x**-1 + x**-3,2)
        1/x
    """
    x = a.parent().gen()
    b = a * x**(i-1)
    return x**(1-i) * (b.numerator() // b.denominator())


def infinite_integral_matrix(mat):
    r"""
    Return a matrix with coefficient in the infinite maximal order and its denominator.

    INPUT:

        - ``mat`` -- Matrix with coefficients in a rational function field K

    OUTPUT:

        - ``int_mat`` -- Matrix with coefficients in K.maximal_order_infinite()
        - ``den`` -- Element of K.maximal_order_infinite such that mat = int_mat/den

    EXAMPLES:

        sage: from vector_bundle.function_field_utility import infinite_integral_matrix
        sage: F.<x> = FunctionField(GF(11))
        sage: mat = matrix([[x, 1], [x**-1, 2]])
        sage: infinite_integral_matrix(mat)
        (
        [    1   1/x]
        [1/x^2   2/x], 1/x
        )
    """
    K = mat[0,0].parent()
    if isinstance(K,FunctionFieldMaximalOrderInfinite_rational):
        return mat,1
    if not isinstance(K,RationalFunctionField):
        raise ValueError('mat must have coefficients in a rational function'
                         + 'field or its infinite maximal order')
    x = K.gen()
    R = K.maximal_order_infinite()
    den = x**min([infinite_valuation(e) for e in mat.list()])
    int_mat = matrix(R,mat.nrows(),mat.ncols(),(den*mat).list())
    return int_mat, den


def infinite_hermite_form(mat,include_zero_cols=True,transformation=False):
    r"""
    Return the hermite form of a matrix with coefficient in a rational infinite maximal order.

    EXAMPLE:
        
        sage: from vector_bundle.function_field_utility import infinite_hermite_form
        sage: K.<x> = FunctionField(GF(3))
        sage: R = K.maximal_order_infinite()
        sage: mat = matrix(R,[[1, x**-1, x**-2, (x**3+1) / x**3], [(2*x+2) / (x**3+2), x**-2, (x**2+2) / (x**4+1), 1]])
        sage: H, T = infinite_hermite_form(mat,transformation=True); H
        [0 0 1 0]
        [0 0 0 1]
        sage: mat*T == H
        True
        sage: H, T = infinite_hermite_form(mat, False, True); H
        [1 0]
        [0 1]
        sage: mat*T == H
        True

    TESTS:

        sage: F.<x> = FunctionField(GF(3))
        sage: R = F.maximal_order_infinite()
        sage: mat = matrix(R,[[x**-1, 0, 2, 1], [0, x**-1, 1, 1], [0, 0, 1, 0], [0, 0, 0, 1]])
        sage: infinite_hermite_form(mat) == mat
        True
    """
    R = mat.base_ring()
    if not isinstance(R,FunctionFieldMaximalOrderInfinite_rational):
        raise ValueError('mat must have base ring a rational infinite maximal'
                         + ' order.')
    n = mat.nrows()
    r = mat.ncols()
    x = R.function_field().gen()
    H = copy(mat)
    T = identity_matrix(R,r)
    #First, make mat upper triangular with diagonal coefficient of the form
    #x**-k.
    for i in range(1,n+1):
        degs = [infinite_valuation(H[-i,j]) for j in range(r+1-i)]
        d0 = min(degs)
        j0 = degs.index(d0)
        E = elementary_matrix(R,r,row1=j0,row2=r-i)
        T *= E
        H *= E
        E = elementary_matrix(R,r,row1=r-i,scale=(x**d0 * H[-i,-i])**-1)
        T *= E
        H *= E
        for j in range(r-i):
            E = elementary_matrix(R,r,row1=r-i,row2=j,scale=-H[-i,j]/H[-i,-i])
            T *= E
            H *= E
    for i in range(2,n+1):
        d = infinite_valuation(H[-i,-i])
        for j in range(1,i):
            E = elementary_matrix(
                R,r,row1=r-i,row2=r-j,
                scale=(infinite_mod(H[-i,-j],d)-H[-i,-j])/H[-i,-i])
            T *= E
            H *= E
    if not include_zero_cols:
        H = H[:,r-n:]
        T = T[:,r-n:]
    if transformation:
        return H,T
    return H


def infinite_ideal_hnf(I,transformation=False):
    r"""
    Return the Hermite form of an ideal of the infinite maximal order.
    """
    O = I.ring()
    K = O.function_field()
    x = K.gen()
    F = K.base_field()
    R = F.maximal_order_infinite()
    n = K.degree()
    order_basis = O.basis()
    order_matrix = matrix(R,[gen.list() for gen in O.basis()]).transpose()
    ideal_basis = I.gens_over_base();
    ideal_matrix = order_matrix**-1 * matrix(F,[gen.list()
                                                for gen in ideal_basis]).transpose()
    mat,den = infinite_integral_matrix(ideal_matrix)
    #This is awkward but if transformation is False, hnf,U = ().hermite_form()
    #will unpack the matrix.
    if transformation:
        hnf,U = infinite_hermite_form(mat, transformation=True)
        return hnf/den,U
    hnf = infinite_hermite_form(mat)
    return hnf/den

def infinite_order_xgcd(ideals):
    r"""
    Performs the extended gcd algorithm for ideals in the infinite order.

    INPUT:

        - ``ideals`` -- list of ideals over the infinite maximal order of a function field

    OUTPUT:
    
        - ``coeffs`` --- list of elements of the function field such that as[i] in ideals[i] and sum(as) = 1
        
    ALGORITHM:

        Proposition 1.3.7 from [Coh00]

    EXAMPLES:

        sage: from vector_bundle.function_field_utility import infinite_order_xgcd
        sage: F.<x> = FunctionField(GF(3))
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y**2 - x**-5 - 1)
        sage: primes = [p.prime_ideal() for p in K.places_infinite()]; len(primes)
        2
        sage: a = infinite_order_xgcd(primes); a
        [2*y + 2, y + 2]
        sage: sum(a)
        1
        sage: all([a[i] in primes[i] for i in range(2)])
        True
    """
    s = len(ideals)
    non_zero_indices = [i for i, ideal in enumerate(ideals) if ideal != 0]
    ideals = [ideal for i, ideal in enumerate(ideals) if ideal != 0]
    order_basis = ideals[0].ring().basis()
    if order_basis[0] != 1:
        raise ValueError('The first element of the basis of the order should'
                         + ' be 1.')
    n = len(order_basis)
    k = len(ideals)
    y = ideals[0].ring().function_field().gen()
    ideals_hnf = [infinite_ideal_hnf(I) for I in ideals]
    ideals_bases = [[sum([order_basis[i]*mat[i,j] for i in range(n)])
                     for j in range(n)]
                    for mat in ideals_hnf]
    C = block_matrix([ideals_hnf])
    C, den = infinite_integral_matrix(C)
    H,U = infinite_hermite_form(C, include_zero_cols=False, transformation=True)
    if not (H/den).is_one():
        raise ValueError("The ideals should be coprime.")
    v = U[:,0].list()
    coefs = [sum([ideals_bases[i][j]*v[n*i+j] for j in range(n)]) for i in range(k)]
    res = [0]*s
    for i, c in zip(non_zero_indices, coefs):
        res[i] = c
    return res


def infinite_approximation(places,valuations,residues):
    r"""
    Return a in the function field of places such that
    (a - residues[i]) has valuation at least valuations[i] at places[i].

    INPUT:

        - ``places`` -- list of FunctionFieldPlace. Infinite places only.
        - ``valuations`` -- list of integers of same length as places.
        - ``residues`` -- list of elements of the function field.

    ALGORITHM:
    
        Proposition 1.3.11 from [Coh00]
    """
    if len(places) == 1:
        return residues[0]
    valuations = [max(0,val) for val in valuations]
    primes = [place.prime_ideal() for place in places]
    I = prod([prime**(val+1) for prime, val in zip(primes, valuations)])
    ideals = [I * prime**(-val-1)
              for prime, val in zip(primes, valuations)]
    coefficients = infinite_order_xgcd(ideals)
    return sum([c * res for c,res in zip(coefficients,residues)])


@cached_function
def safe_uniformizers(K):
    r"""
    Return a safe uniformizer and an infinite place of self._function_field
    A uniformizer is safe if its valuation at other infinite places is 0.

    EXAMPLES:

        sage: from vector_bundle.function_field_utility import safe_uniformizers
        sage: F.<x> = FunctionField(GF(3))
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y^2 - x**-5 - 1)
        sage: places = K.places_infinite()
        sage: pis = safe_uniformizers(K)
        sage: all([(pi.valuation(place) == 1 and i == j) or (pi.valuation(place) == 0 and i != j) for (i,pi) in enumerate(pis) for (j, place) in enumerate(places)])
        True

    """
    places = all_infinite_places(K)
    n = len(places)
    return [infinite_approximation(
            places,
            [2 if p == place else 1 for p in places],
            [place.local_uniformizer() if p == place else 1 for p in places])
            for place in places]


class FunctionFieldCompletionCustom(Map):
    """
    Completions on function fields.

    Allows for choice of uniformizer.

    INPUT:

    - ``field`` -- function field

    - ``place`` -- place of the function field

    - ``pi`` -- a local uniformizer at place

    - ``name`` -- string for the name of the series variable

    - ``prec`` -- positive integer; default precision

    - ``gen_name`` -- string; name of the generator of the residue
      field; used only when place is non-rational

    EXAMPLES::

        sage: from vector_bundle.function_field_utility import FunctionFieldCompletionCustom
        sage: K.<x> = FunctionField(GF(2)); _.<Y> = K[]
        sage: L.<y> = K.extension(Y^2 + Y + x + 1/x)
        sage: p = L.places_finite()[0]
        sage: m = FunctionFieldCompletionCustom(L,p)
        sage: m
        Completion map:
          From: Function field in y defined by y^2 + y + (x^2 + 1)/x
          To:   Laurent Series Ring in s over Finite Field of size 2
        sage: m(x)
        s^2 + s^3 + s^4 + s^5 + s^7 + s^8 + s^9 + s^10 + s^12 + s^13
        + s^15 + s^16 + s^17 + s^19 + O(s^22)
        sage: m(y)
        s^-1 + 1 + s^3 + s^5 + s^7 + s^9 + s^13 + s^15 + s^17 + O(s^19)
        sage: m(x*y) == m(x) * m(y)
        True
        sage: m(x+y) == m(x) + m(y)
        True

    The variable name of the series can be supplied. If the place is not
    rational such that the residue field is a proper extension of the constant
    field, you can also specify the generator name of the extension::

        sage: p2 = L.places_finite(2)[0]
        sage: p2
        Place (x^2 + x + 1, x*y + 1)
        sage: m2 = FunctionFieldCompletionCustom(L, p2, name='t', gen_name='b')
        sage: m2(x)
        (b + 1) + t + t^2 + t^4 + t^8 + t^16 + O(t^20)
        sage: m2(y)
        b + b*t + b*t^3 + b*t^4 + (b + 1)*t^5 + (b + 1)*t^7 + b*t^9 + b*t^11
        + b*t^12 + b*t^13 + b*t^15 + b*t^16 + (b + 1)*t^17 + (b + 1)*t^19 + O(t^20)

    The choice of local uniformizer used for the expansion can be supplied.

        sage: from vector_bundle.function_field_utility import safe_uniformizers
        sage: from vector_bundle.function_field_utility import all_infinite_places 
        sage: F.<x> = FunctionField(GF(3))
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y^2 - x**-5 - 1)
        sage: pi = safe_uniformizers(K)[0]
        sage: place = all_infinite_places(K)[0]
        sage: f = 1 / (1-pi)
        sage: m3 = FunctionFieldCompletionCustom(K, place, pi)
        sage: m3(f)
        1 + s + s^2 + s^3 + s^4 + s^5 + s^6 + s^7 + s^8 + s^9 + s^10 + s^11 + 
        s^12 + s^13 + s^14 + s^15 + s^16 + s^17 + s^18 + s^19 + O(s^20)
    """
    def __init__(self, field, place, pi=None, name=None, prec=None, gen_name=None):
        """
        Initialize.

        EXAMPLES::

            sage: # needs sage.rings.finite_rings sage.rings.function_field
            sage: K.<x> = FunctionField(GF(2)); _.<Y> = K[]
            sage: L.<y> = K.extension(Y^2 + Y + x + 1/x)
            sage: p = L.places_finite()[0]
            sage: m = L.completion(p)
            sage: m
            Completion map:
              From: Function field in y defined by y^2 + y + (x^2 + 1)/x
              To:   Laurent Series Ring in s over Finite Field of size 2
        """
        if name is None:
            name = 's'  # default

        if gen_name is None:
            gen_name = 'a'  # default

        k, from_k, to_k = place.residue_field(name=gen_name)

        self._place = place
        if pi is None:
            self._pi = place.local_uniformizer()
        else:
            self._pi = pi

        self._gen_name = gen_name

        if prec is infinity:
            from sage.rings.lazy_series_ring import LazyLaurentSeriesRing
            codomain = LazyLaurentSeriesRing(k, name)
            self._precision = infinity
        else:  # prec < infinity:
            # if prec is None, the Laurent series ring provides default precision
            from sage.rings.laurent_series_ring import LaurentSeriesRing
            codomain = LaurentSeriesRing(k, name=name, default_prec=prec)
            self._precision = codomain.default_prec()

        Map.__init__(self, field, codomain)

    def _repr_type(self) -> str:
        """
        Return a string containing the type of the map.

        EXAMPLES::

            sage: # needs sage.rings.finite_rings sage.rings.function_field
            sage: K.<x> = FunctionField(GF(2)); _.<Y> = K[]
            sage: L.<y> = K.extension(Y^2 + Y + x + 1/x)
            sage: p = L.places_finite()[0]
            sage: m = L.completion(p)
            sage: m  # indirect doctest
            Completion map:
              From: Function field in y defined by y^2 + y + (x^2 + 1)/x
              To:   Laurent Series Ring in s over Finite Field of size 2
        """
        return 'Completion'

    def _call_(self, f):
        """
        Call the completion for f

        EXAMPLES::

            sage: # needs sage.rings.finite_rings sage.rings.function_field
            sage: K.<x> = FunctionField(GF(2)); _.<Y> = K[]
            sage: L.<y> = K.extension(Y^2 + Y + x + 1/x)
            sage: p = L.places_finite()[0]
            sage: m = L.completion(p)
            sage: m(y)
            s^-1 + 1 + s^3 + s^5 + s^7 + s^9 + s^13 + s^15 + s^17 + O(s^19)
        """
        if f.is_zero():
            return self.codomain().zero()
        if self._precision is infinity:
            return self._expand_lazy(f)
        else:
            return self._expand(f, prec=None)

    def _call_with_args(self, f, args, kwds):
        """
        Call the completion with ``args`` and ``kwds``.

        EXAMPLES::

            sage: # needs sage.rings.finite_rings sage.rings.function_field
            sage: K.<x> = FunctionField(GF(2)); _.<Y> = K[]
            sage: L.<y> = K.extension(Y^2 + Y + x + 1/x)
            sage: p = L.places_finite()[0]
            sage: m = L.completion(p)
            sage: m(x+y, 10)  # indirect doctest
            s^-1 + 1 + s^2 + s^4 + s^8 + O(s^9)
        """
        if f.is_zero():
            return self.codomain().zero()
        if self._precision is infinity:
            return self._expand_lazy(f, *args, **kwds)
        else:
            return self._expand(f, *args, **kwds)

    def _expand(self, f, prec=None):
        """
        Return the Laurent series expansion of f with precision ``prec``.

        INPUT:

        - ``f`` -- element of the function field

        - ``prec`` -- positive integer; relative precision of the series

        EXAMPLES::

            sage: # needs sage.rings.finite_rings sage.rings.function_field
            sage: K.<x> = FunctionField(GF(2)); _.<Y> = K[]
            sage: L.<y> = K.extension(Y^2 + Y + x + 1/x)
            sage: p = L.places_finite()[0]
            sage: m = L.completion(p)
            sage: m(x, prec=20)  # indirect doctest
            s^2 + s^3 + s^4 + s^5 + s^7 + s^8 + s^9 + s^10 + s^12 + s^13 + s^15
            + s^16 + s^17 + s^19 + O(s^22)
        """
        if prec is None:
            prec = self._precision

        place = self._place
        F = place.function_field()
        der = F.higher_derivation()

        k, from_k, to_k = place.residue_field(name=self._gen_name)
        sep = self._pi

        val = f.valuation(place)
        e = f * sep**(-val)

        coeffs = [to_k(der._derive(e, i, sep)) for i in range(prec)]
        return self.codomain()(coeffs, val).add_bigoh(prec + val)

    def _expand_lazy(self, f):
        """
        Return the lazy Laurent series expansion of ``f``.

        INPUT:

        - ``f`` -- element of the function field

        EXAMPLES::

            sage: # needs sage.rings.finite_rings sage.rings.function_field
            sage: K.<x> = FunctionField(GF(2)); _.<Y> = K[]
            sage: L.<y> = K.extension(Y^2 + Y + x + 1/x)
            sage: p = L.places_finite()[0]
            sage: m = L.completion(p, prec=infinity)
            sage: e = m(x); e
            s^2 + s^3 + s^4 + s^5 + s^7 + s^8 + ...
            sage: e.coefficient(99)  # indirect doctest
            0
            sage: e.coefficient(100)
            1
        """
        place = self._place
        F = place.function_field()
        der = F.higher_derivation()

        k, from_k, to_k = place.residue_field(name=self._gen_name)
        sep = self._pi

        val = f.valuation(place)
        e = f * sep**(-val)

        def coeff(s, n):
            return to_k(der._derive(e, n - val, sep))

        return self.codomain().series(coeff, valuation=val)

    def default_precision(self):
        """
        Return the default precision.

        EXAMPLES::

            sage: # needs sage.rings.finite_rings sage.rings.function_field
            sage: K.<x> = FunctionField(GF(2)); _.<Y> = K[]
            sage: L.<y> = K.extension(Y^2 + Y + x + 1/x)
            sage: p = L.places_finite()[0]
            sage: m = L.completion(p)
            sage: m.default_precision()
            20
        """
        return self._precision

def local_expansion(place,pi,f):
    r"""
    Return a function giving the i-th coefficient of the expansion of f.

    This uses code from sage.rings.function_field.maps.FunctionFieldCompletion.
    While somewhat redundant, it adds the possibility to chose the uniformizer
    with respect to which the expansion is computed.

    INPUT:

        - ``place`` -- FunctionFieldPlace; the place at which to expand
        - ``pi`` -- The uniformizer giving variable for the power series
        - ``f`` -- The function to expand

    OUTPUT:

        - a function taking as input an integer i and returning the coefficient of degree i

    EXAMPLES:

    """
def residue(place,pi,f):
    r"""
    Return the residue of constant répartition f at place with respect
    to local uniformizer pi.
    """
    if pi.valuation(place) != 1:
        raise ValueError('pi must be a local uniformizer at place')
    k, _, _ = place.residue_field()
    kc = place.function_field().constant_base_field()
    exp = local_expansion(place,pi,f)
    high_res = exp(-1)
    return k.over(kc)(high_res).trace()
    

def invert_trace(field,base,target):
    r"""
    Find an element of trace 1 over base in field.

    EXAMPLES:
        sage: from vector_bundle.function_field_utility import invert_trace
        sage: base = GF(9)
        sage: field = GF(9**3)
        sage: a = invert_trace(field, base, 1); a
        2*z6^4 + 2*z6^3 + z6 + 1
        sage: field.over(base)(a).trace()
        1
    """
    if field == base:
        if target not in field:
            raise ValueError('Since field = base, target should be an element'
                             + ' of field')
        return target
    as_ext = field.over(base)
    d = as_ext.degree(base)
    t = as_ext.gen()
    i = [(t**j).trace() != 0 for j in range(d)].index(True)
    return field(target * t**i/((t**i).trace()))

def insert_row(mat,i,row):
    r"""
    Return matrix mat with row inserted in ith position.

    EXAMPLES:
        sage: from vector_bundle.function_field_utility import insert_row
        sage: mat = matrix(GF(3), 2, 2, [1, 2, 2, 1])
        sage: insert_row(mat, 1, [0, 1])
        [1 2]
        [0 1]
        [2 1]
    """
    return matrix([mat[j] for j in range(i)]
                  + [row]
                  + [mat[j] for j in range(i,mat.nrows())])


def norm(v):
    r"""
    Return the norm of vector v: the maximal degree of its coefficients.

    Input:

        - v -- vector with coefficients in a RationalFunctionField

    EXAMPLES:

        sage: from vector_bundle.function_field_utility import norm
        sage: R.<x> = GF(3)[]
        sage: v = vector([x^3 + 3 + 1, x^2])
        sage: norm(v)
        3
    """
    return max([c.degree() for c in v.list()])

def smallest_norm_first(mat,i = 0,norms=[]):
    r"""
    Swap rows of M so that the i-th row has smaller norm than rows below.

    INPUT:

        ``mat`` -- matrix with coefficients in a RationalFunctionField
        ``i`` -- integer (default: `0`)

    EXAMPLES:

        sage: from vector_bundle.function_field_utility import smallest_norm_first
        sage: R.<x> = GF(3)[]
        sage: mat = matrix([[1, 1], [x^2, x^3], [1, x]])
        sage: smallest_norm_first(mat, 1)
        [0, 1, 3]
        sage: mat
        [  1   1]
        [  1   x]
        [x^2 x^3]
    """
    if norms == []:
        norms = [norm(row) for row in mat]
    j = norms[i:].index(min(norms[i:]))
    mat.swap_rows(i,i+j)
    n = norms[i]
    norms[i] = norms[j+i]
    norms[j+i] = n
    return norms


def finite_order_xgcd(left, right):
    r"""
    Compute `a \in left` and `b \in right` such that `a + b = 1`

    INPUT:

    -a: FunctionFieldIdeal_polymod: ideal of a finite maximal order
    -b: FunctionFieldIdeal_polymod: ideal of the same maximal order

    ALGORITHM:

    [Coh00]_ Algorithm 1.3.2

    EXAMPLES ::

        sage: from vector_bundle.function_field_utility import finite_order_xgcd
        sage: F.<x> = FunctionField(GF(7))
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y^2 - x^3 - x)
        sage: places = K.places_finite()
        sage: left = places[0].prime_ideal()
        sage: right = places[1].prime_ideal()
        sage: a, b = finite_order_xgcd(left, right)
        sage: a in left
        True
        sage: b in right
        True
        sage: a + b
        1
    """
    O = left.base_ring()
    O_basis = O.basis()
    m_left = left.hnf()
    n = m_left.nrows()
    m_right = right.hnf()
    c = block_matrix([[m_left], [m_right]])
    h, u = c.hermite_form(False, True)
    if not h.is_one():
        raise ValueError('The ideals left and right must be coprime.')
    x = u[0,:n].list()
    a = sum([c*e for c, e in zip(x,left.gens_over_base())])
    return a, 1-a


def euclidean_step(ideal_a, ideal_b, a, b, d=None):
    r"""
    Let `d = ideal_a a + ideal_b b`. Return `u \in ideal_a d^-1` and
    `v \in ideal_b d^-1` such that au + bv = 1

    ALGORITHM:

    [Coh00]_ Theorem 1.3.3

    EXAMPLES ::

        sage: from vector_bundle.function_field_utility import euclidean_step
        sage: F.<x> = FunctionField(GF(7))
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y^2 - x^3 - x)
        sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
        sage: a = x^2*y + 3
        sage: b = 2*y*x^5
        sage: d = a*ideals[0] + b*ideals[1]
        sage: u, v = euclidean_step(ideals[0], ideals[1], a, b)
        sage: u in ideals[0] * d^-1
        True
        sage: v in ideals[1] * d^-1
        True
        sage: a*u + b*v
        1
    """
    infinite = isinstance(ideal_a.base_ring(),FunctionFieldOrderInfinite)
    if a == 0:
        return 0, b^-1
    if b == 0:
        return a^-1, 0
    if d == None:
        d = a*ideal_a + b*ideal_b
    I = a * ideal_a * d**-1
    J = b * ideal_b * d**-1
    #It would make sense to distinguish between finite and infinite order
    #in a unified xgcd function, but the hnf form for infinite ideals
    #needs to be refactored: we currently use opposite convention from
    #that of sage.
    if infinite:
        s, t = infinite_order_xgcd([I,J])
    else:
        s, t = finite_order_xgcd(I, J)
    return s/a, t/b


def finite_integral_quotient(left, right):
    return (left.numerator()*right.denominator()) // (left.denominator())*(right.numerator())


def infinite_integral_quotient(left, right):
    if left == 0:
        return 0
    r = left / right
    x = left.parent().gen()
    return x**(r.denominator().degree() - r.numerator().degree())


def hnf_reduction_mod_ideal(ideal, elem):
    r"""
    Reduce an element of a function field \(K\) modulo an ideal of a maximal
    order of K
    """
    if isinstance(ideal, FunctionFieldIdealInfinite):
        quotient = infinite_integral_quotient
        hnf = infinite_ideal_hnf(ideal)
    else:
        quotient = finite_integral_quotient
        hnf = ideal.hnf()
    n = hnf.ncols()
    basis = ideal.base_ring().basis()
    basis_matrix = matrix([e.list() for e in basis]).transpose()**-1
    y = basis_matrix * matrix(n,1,elem.list())
    for i in range(n - 1, -1, -1):
        q = quotient(y[i,0],hnf[i,i])
        y -= q * hnf[:,i]
    y = sum([y[i,0]*e for i, e in enumerate(basis)])
    return y


def pseudo_hermite_form(ideals, mat, include_zero_cols=True, transformation=False):
    r"""
    Return the hermite form of the pseudo-matrix ``(ideals, mat)`` with
    coefficients in a function field and ideals in a maximal order.

    WARNING:

    Uses the opposite convention from sage for hermite forms, aligns with
    Cohen's book instead.

    ALGORITHM:

    - Algorithm 1.4.7 from [Coh00]_

    EXAMPLES ::

        sage: from vector_bundle.function_field_utility import pseudo_hermite_form
        sage: F.<x> = FunctionField(GF(7))
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y^2 - x^3 - x)
        sage: ideals = [P.prime_ideal() for P in K.places_finite()[:3]]
        sage: mat = matrix(K, [[1, x, y],[2, x+1, y+1]])
        sage: h_ideals, h, u = pseudo_hermite_form(ideals, mat, transformation=True)
        sage: h
        [          0           1 3*x^3 + 4*x]
        [          0           0           1]
        sage: h == mat * u
        True
        sage: all([u[i,j] in ideals[i] * h_ideals[j]^-1 for i in range(3) for j in range(3)])
        True
        sage: prod(ideals) == u.determinant() * prod(h_ideals)
        True
    """
    K = mat.base_ring()
    k = mat.ncols()
    n = mat.nrows()
    U = identity_matrix(K,k)
    h = copy(mat)
    h_ideals = copy(ideals)
    j = k-1
    for i in range(n-1, -1, -1):
        #Check zero
        if all([h[i,m] == 0 for m in range(j+1)]):
            continue
        m = [h[i,m] == 0 for m in range(j+1)].index(False)
        h[:,m], h[:,j] = h[:,j], h[:,m]
        U[:,m], U[:,j] = U[:,j], U[:,m]
        h_ideals[m], h_ideals[j] = h_ideals[j], h_ideals[m]
        #Put 1 on the main diagonal
        a = h[i,j]**-1
        h_ideals[j] *= h[i,j]
        h[:,j] *= a
        U[:,j] *= a
        for m in range(j-1,-1,-1):
            if h[i,m] == 0:
                continue
            #Euclidean step
            partial = h[i,m]*h_ideals[m] + h_ideals[j]
            u, v = euclidean_step(h_ideals[m], h_ideals[j],
                                       h[i,m], 1, partial)
            U[:, m], U[:, j] = U[:, m] - h[i, m]*U[:, j], u*U[:, m] + v*U[:, j]
            h[:, m], h[:, j] = h[:, m] - h[i, m]*h[:, j], u*h[:, m] + v*h[:, j]
            h_ideals[m], h_ideals[j] = h_ideals[m] * h_ideals[j] * partial**-1, partial
        #Row reduction step
        for m in range(j+1,k):
            ideal = h_ideals[m]**-1 * h_ideals[j]
            q = h[i, m] -  hnf_reduction_mod_ideal(ideal, h[i, m])
            U[:, m] -= q*U[:, j]
            h[:, m] -= q*h[:, j]
        j -=1
    if not include_zero_cols:
        first_nonzero = [h[:,j].is_zero() for j in range(k)].index(False)
        h = h[:,first_nonzero:]
        h_ideals = h_ideals[first_nonzero:]
        U = U[:,first_nonzero:]
    if transformation:
        return h_ideals, h, U
    return h_ideals, h

def hermite_form_infinite_polymod(mat, include_zero_cols=True, transformation=False):
    r"""
    Return the hermite normal form of mat.

    EXAMPLES ::
        sage: from vector_bundle.function_field_utility import hermite_form_infinite_polymod
        sage: from vector_bundle.function_field_utility import all_infinite_places 
        sage: F.<x> = FunctionField(GF(7))
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y^2 - x^3 - x)
        sage: mat = matrix(K,[[1,x^-1,y^-1],[2,(x+1)^-1,(y+1)^-1]])
        sage: h, u = hermite_form_infinite_polymod(mat, transformation=True)
        sage: h
        [                  0 (4*x + 1)/(x^2 + x)     (4*x^2 + 6)/x^2]
        [                  0                   0                   1]
        sage: h == mat * u
        True
        sage: O = K.maximal_order_infinite()
        sage: all([c in O for c in u.list()])
        True
        sage: all([u.determinant().valuation(place) == 0 for place in all_infinite_places(K)])
        True
    """
    K = mat.base_ring()
    O = K.maximal_order_infinite()
    pis = safe_uniformizers(K)
    places = all_infinite_places(K)
    mins = [min([m.valuation(place) for m in mat.list()]) for place in places]
    den = prod([pi**min(-m,0) for pi, m in zip(pis, mins)])
    h = den*mat
    k = mat.ncols()
    n = mat.nrows()
    U = identity_matrix(K,k)
    j = k-1
    for i in range(n-1, -1, -1):
        if all([h[i,m] == 0 for m in range(j+1)]):
            continue
        min_vals = [min([h[i,m].valuation(place) for m in range(j+1)])
                    for place in places]
        gcd = prod([pi**m for pi, m in zip(pis, min_vals)])
        #put gcd on the diagonal
        ideals = [O.ideal(h[i,m]/gcd) if not h[i,m].is_zero() else 0
                  for m in range(j+1)]
        coefs = infinite_order_xgcd(ideals)
        ell = [c == 0 for c in coefs].index(False)
        U[:,j], U[:, ell] = gcd*sum([(c/h[i,ell])*U[:,m]
                                   for m,c in enumerate(coefs)]), U[:, j]
        h[:,j], h[:, ell] = gcd*sum([(c/h[i,ell])*h[:,m]
                                   for m,c in enumerate(coefs)]), h[:, j]
        assert(all([u in O for u in U.list()]))
        #eliminate coefficients left of diagonal
        for m in range(j):
            c = h[i,m]/h[i,j]
            U[:,m] -= c*U[:,j]
            h[:,m] -= c*h[:,j]
            assert(all([u in O for u in U.list()]))
        #reduce coefficients right of diagonal
        for m in range(j+1,k):
            ideal = O.ideal(h[i,j])
            q = (h[i, m] - hnf_reduction_mod_ideal(ideal,h[i, m]))/h[i,j]
            U[:,m] -= q*U[:,j]
            h[:,m] -= q*h[:,j]
        j-=1
    h /= den
    if not include_zero_cols:
        first_nonzero = [h[:,j].is_zero() for j in range(k)].index(False)
        h = h[:,first_nonzero:]
        U = U[:,first_nonzero:]
    if transformation:
        return h, U
    return h


def full_rank_matrix_in_completion(mat, place=None, pi=None):
    r"""
    Return a full rank matrix with coefficients in the constant base field.

    Its columns are concatenations of expansions of the coefficients in the
    columns of mat.
    """
    K = mat.base_ring()
    k = K.constant_base_field()
    s = mat.ncols()
    r = mat.nrows()
    if place is None:
        if isinstance(K, RationalFunctionField):
            place = K.gen().zeros()[0]
        else:
            place = K.get_place(1)
    Kp = FunctionFieldCompletionCustom(K, place, pi, prec=infinity, name="pi", gen_name="b")
    exps = [[Kp(c) for c in row] for row in mat]
    vals = [min([mat[i,j].valuation(place) for j in range(s)])
            for i in range(r)]
    ell = 0
    N = matrix(k,0,s)
    while N.rank() < s:
        for i in range(r):
            row = [exps[i][j].coefficient(vals[i] + ell) for j in range(s)]
            N = insert_row(N, (i+1)*(ell+1) - 1, row)
        ell += 1
    return N, Kp, vals
