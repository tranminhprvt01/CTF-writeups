r"""
This module implements the HomBundle class, for vector bundles constructed
as homomorphism sheaves between two vector bundles.

The class inherits from the VectorBundle class, but sections, either local
or global, are displayed as matrices.

EXAMPLES ::

    sage: from vector_bundle import VectorBundle, trivial_bundle, savin_bundle
    sage: F.<x> = FunctionField(GF(3))
    sage: R.<y> = F[]
    sage: K.<y> = F.extension(y^2 - x^5 - 1)

We construct a vector bundle of rank 2 and degree 4::

    sage: F = VectorBundle(K, 3 * K.places_infinite()[0].divisor())
    sage: F1 = VectorBundle(K, 2 * K.places_finite()[0].divisor())
    sage: F2 = VectorBundle(K, 2 * K.places_finite()[1].divisor())
    sage: V = savin_bundle(K, 2, 4, F, F1, F2); V.h0()
    [(1, 0), (2*x, 1)]

We construct the ``HomBundle`` from `\mathcal{O}_X^2` to ``V``. Its global
sections should represent linear maps from `k^2` to  `H^0(V)`, where `k`
is the constant field of `K`::

    sage: domain = trivial_bundle(K).direct_sum_repeat(2)
    sage: hom_bundle = domain.hom(V); hom_bundle.h0()
    [
    [1 0]  [2*x   0]  [0 1]  [  0 2*x]
    [0 0], [  1   0], [0 0], [  0   1]
    ]
"""
###########################################################################
#  Copyright (C) 2024 Mickaël Montessinos (mickael.montessinos@mif.vu.lt),#
#                                                                         #
#  Distributed under the terms of the GNU General Public License (GPL)    #
#  either version 3, or (at your option) any later version                #
#                                                                         #
#  http://www.gnu.org/licenses/                                           #
###########################################################################

from sage.misc.cachefunc import cached_method
from sage.matrix.constructor import matrix
from sage.matrix.special import identity_matrix
from sage.modules.free_module_element import vector
from sage.categories.all import Algebras
from sage.algebras.all import FiniteDimensionalAlgebra
from vector_bundle import VectorBundle
from vector_bundle import function_field_utility, algebras

class HomBundle(VectorBundle):
    r"""
    Vector bundles representing homomorphism sheaves of vector bundles.

    EXAMPLES ::

        sage: from vector_bundle import VectorBundle
        sage: F.<x> = FunctionField(GF(3))
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y^2 + x + 2)
        sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
        sage: g_finite = matrix([[1, x], [2, y]])
        sage: g_infinite = matrix([[x, 1], [2, y]])
        sage: V1 = VectorBundle(K, ideals, g_finite, g_infinite)
        sage: V2 = VectorBundle(K, K.places_infinite()[0].divisor())
        sage: V = V1.hom(V2); V
        Homomorphism bundle from Vector bundle of rank 2 over Function field in y defined by y^2 + x + 2 to Vector bundle of rank 1 over Function field in y defined by y^2 + x + 2
    """
    def __init__(self,domain,codomain):
        if (not isinstance(domain,VectorBundle) or
            not isinstance(codomain,VectorBundle)):
            raise TypeError
        if domain._function_field != codomain._function_field:
            raise ValueError
        self._domain = domain
        self._codomain = codomain
        ideals = [ideal_domain**-1 * ideal_codomain
                  for ideal_domain in domain._ideals
                  for ideal_codomain in codomain._ideals]
        g_finite = (domain._g_finite.transpose()**-1)\
        .tensor_product(codomain._g_finite)
        g_infinite = (domain._g_infinite.transpose()**-1)\
        .tensor_product(codomain._g_infinite)
        super().__init__(domain._function_field, ideals,g_finite,g_infinite)

    def __hash__(self):
        return hash((self._domain, self._codomain))

    def __eq__(self,other):
        return (super().__eq__(other)
                and self._domain == other._domain
                and self._codomain == other._codomain)

    def _repr_(self):
        return "Homomorphism bundle from %s to %s" % (
                self._domain,
                self._codomain,
                )

    def domain(self):
        r"""
        Return the domain of self

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: L1 = VectorBundle(F, x.poles()[0].divisor())
            sage: L2 = VectorBundle(F, x.zeros()[0].divisor())
            sage: V = L1.hom(L2); V.domain() == L1
            True
        """
        return self._domain

    def codomain(self):
        r"""
        Return the codomain of self

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: L1 = VectorBundle(F, x.poles()[0].divisor())
            sage: L2 = VectorBundle(F, x.zeros()[0].divisor())
            sage: V = L1.hom(L2); V.codomain() == L2
            True
        """
        return self._codomain

    def _vector_to_matrix(self,vec):
        r"""
        Return the matrix of the homomorphism encoded by vector vec.
        """
        return matrix(self._domain.rank(),self._codomain.rank(),vec).transpose()

    def _matrix_to_vector(self,mat):
        r"""
        Inverse operation of _vector_to_matrix()
        """
        return vector(mat.transpose().list())

    def basis_finite(self):
        r"""
        Return basis of the finite lattice of the hom bundle.

        OUTPUT:
            
        - The basis elements are represented as matrices.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1, x], [2, y]])
            sage: g_infinite = matrix([[x, 1], [2, y]])
            sage: V1 = VectorBundle(K, ideals, g_finite, g_infinite)
            sage: O = K.maximal_order()
            sage: V2 = VectorBundle(K, K.places_finite()[2].prime_ideal(),1,x^2)
            sage: V = V1.hom(V2)
            sage: V.basis_finite() 
            [[(x/(x^2 + x + 2))*y + (x + 2)/(x^2 + x + 2)   (x/(x^2 + x + 2))*y + 2*x^2/(x^2 + x + 2)],
             [(2/(x^2 + x + 2))*y + x/(x^2 + x + 2) (2/(x^2 + x + 2))*y + x/(x^2 + x + 2)]]
        """
        basis = super().basis_finite()
        return [self._vector_to_matrix(v) for v in basis]

    def basis_infinite(self):
        r"""
        Return basis of the infinite lattice of the hom bundle.

        OUTPUT:

        - The basis elements are represented as matrices.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1, x], [2, y]])
            sage: g_infinite = matrix([[x, 1],[2, y]])
            sage: V1 = VectorBundle(K, ideals,g_finite,g_infinite)
            sage: O = K.maximal_order()
            sage: V2 = VectorBundle(K, K.places_finite()[2].prime_ideal(),1,x^2)
            sage: V = V1.hom(V2)
            sage: V.basis_infinite()
            [[(x^2/(x^3 + 2*x^2 + 1))*y + (x^4 + 2*x^3)/(x^3 + 2*x^2 + 1) (x^3/(x^3 + 2*x^2 + 1))*y + 2*x^2/(x^3 + 2*x^2 + 1)],
            [(2*x^3/(x^3 + 2*x^2 + 1))*y + x^2/(x^3 + 2*x^2 + 1) (2*x^4/(x^3 + 2*x^2 + 1))*y + x^3/(x^3 + 2*x^2 + 1)]]
        """
        basis = super().basis_infinite()
        return [self._vector_to_matrix(v) for v in basis]

    def basis_local(self,place):
        r"""
        Return basis of the infinite lattice of the hom bundle.

        OUTPUT:

        - The basis elements are represented as matrices.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1,x],[2,y]])
            sage: g_infinite = matrix([[x,1],[2,y]])
            sage: V1 = VectorBundle(K, ideals,g_finite,g_infinite)
            sage: O = K.maximal_order()
            sage: V2 = VectorBundle(K, K.places_finite()[2].prime_ideal(),1,x^2)
            sage: V = V1.hom(V2)
            sage: place = K.places_finite()[0]
            sage: V.basis_local(place)
            [[(1/(x^2 + x + 2))*y + (x + 2)/(x^3 + x^2 + 2*x) (1/(x^2 + x + 2))*y + 2*x/(x^2 + x + 2)],
            [(2/(x^2 + x + 2))*y + x/(x^2 + x + 2) (2/(x^2 + x + 2))*y + x/(x^2 + x + 2)]]
            sage: all([all([(mat * g_finite)[0, j].valuation(place) >= (V2._ideals[0] * V1._ideals[j]**-1).divisor().valuation(place) for j in range(2)]) for mat in V.basis_local(place)])
            True
        """
        basis = super().basis_local(place)
        return [self._vector_to_matrix(v) for v in basis]

    def hom(self, other):
        r"""
        Return the Hom bundle from self to other.

        If other is a vector bundle, this is the hom bundle from ``self._codomain``
        to ``self._domain.tensor_product(other)``.
        If other is also a hom bundle, this is the hom bundle from
        ``self.codomain().tensor_product(other.domain())``
        to ``self.domain().tensor_product(other.codomain()``

        EXAMPLES::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(7))
            sage: L1 = VectorBundle(F, 2*x.zeros()[0].divisor())
            sage: L2 = VectorBundle(F, -3*x.poles()[0].divisor())
            sage: hom = L1.hom(L2)
            sage: T = L1.tensor_product(L2)
            sage: hom.hom(hom) == T.end()
            True
        """
        if isinstance(other, HomBundle):
            return self._codomain.tensor_product(other._domain)\
                    .hom(self._domain.tensor_product(other._codomain))
        return self._codomain.hom(self._domain.tensor_product(other))

    def tensor_product(self,other):
        r"""
        Return the tensor product of a hom bundle and a vector bundle.
        This is the same thing as
        ``self._domain.hom(self._codomain.tensor_product(other))``

        EXAMPLES::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(7))
            sage: L1 = VectorBundle(F, 2*x.zeros()[0].divisor())
            sage: L2 = VectorBundle(F, -3*x.poles()[0].divisor())
            sage: hom = L1.hom(L2)
            sage: hom2 = L1.hom(L2.tensor_product(L1))
            sage: hom.tensor_product(L1) == hom2
            True
        """
        return self._domain.hom(self._codomain.tensor_product(other))

    def conorm(self,K):
        r"""
        Return the conorm of a hom bundle.
        
        It is the same thing as the hom bundle of the conorms of its domain and
        codomain.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: ideals = [P.prime_ideal() for P in F.places_finite()[:2]]
            sage: g_finite = matrix([[1, x], [2, x]])
            sage: g_infinite = matrix([[x, 1], [2, x]])
            sage: V1 = VectorBundle(F, ideals, g_finite, g_infinite)
            sage: ideals = [P.prime_ideal() for P in F.places_finite()[1:3]]
            sage: g_finite = matrix([[0, x], [1, 1/x]])
            sage: g_infinite = matrix([[x, 2*x^2], [2, 1]])
            sage: V2 = VectorBundle(F, ideals, g_finite, g_infinite)
            sage: V1.conorm(K).hom(V2.conorm(K)) == V1.hom(V2).conorm(K)
            True
        """

        return self._domain.conorm(K).hom(self._codomain.conorm(K))

    def h0(self):
        r"""
        Returns the 0th cohomology group of the hom bundle.
        The global sections are output in matrix form, they are the global
        homomorphisms from ``self._domain`` to ``self._codomain``.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1, x], [2, y]])
            sage: g_infinite = matrix([[x, 1], [2, y]])
            sage: V1 = VectorBundle(K, ideals, g_finite, g_infinite)
            sage: O = K.maximal_order()
            sage: V2 = VectorBundle(K, K.places_finite()[2].prime_ideal(),1,x^2)
            sage: V = V1.hom(V2)
            sage: h0 = V.h0(); len(h0) == V.degree() + (1-K.genus())*V.rank()
            True
            sage: all([all([(mat * g_finite)[0, j] in V2._ideals[0] * V1._ideals[j]**-1 for j in range(2)]) for mat in h0])
            True
            sage: O_infinity = K.maximal_order_infinite()
            sage: all([all([a in O_infinity for a in (x**-2 * mat * g_infinite).list()]) for mat in h0])
            True
        """
        if self._h0 is not None:
            return self._h0
        h0 = super().h0()
        h0 = [self._vector_to_matrix(v) for v in h0]
        self._h0 = h0
        return h0

    def coordinates_in_h0(self, mat):
        r"""
        Return the coordinates in the basis of ``self.h0()`` of the matrix
        ``mat``
        EXAMPLES::

            sage: from vector_bundle import trivial_bundle, canonical_bundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^4 - x^-2 - 1)
            sage: triv = trivial_bundle(K)
            sage: can = canonical_bundle(K)
            sage: V1 = triv.direct_sum(can)
            sage: V2 = can.direct_sum(triv)
            sage: hom = V1.hom(V2)
            sage: hom.coordinates_in_h0(matrix([[0, 1], [1, 0]]))
            (0, 1, 1, 0)
        """
        if self._h0_matrix is None:
            vec_h0 = [self._matrix_to_vector(m) for m in self.h0()]
            basis_mat = matrix(self._function_field, vec_h0).transpose()
            self._h0_matrix, self._h0_Kp, self._h0_vs =\
                    function_field_utility.full_rank_matrix_in_completion(basis_mat)
        vec_f = self._matrix_to_vector(mat)
        res = VectorBundle.coordinates_in_h0(self, vec_f, check=False)
        if mat == self.h0_from_vector(res):
            return res
        return None

    def image(self, f):
        r"""
        Return an image of global homomorphism ``f`` which is an element of
        `H^0(\mathrm{self})`.

        That is, a vector bundle `V` together with an injective morphism of `V`
        into ``self.codomain`` such that the image of `V` in ``self.codomain``
        is also the image of ``f``.

        EXAMPLES ::

            sage: from vector_bundle import trivial_bundle, canonical_bundle
            sage: F.<x> = FunctionField(GF(7))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: triv = trivial_bundle(K)
            sage: can = canonical_bundle(K)
            sage: V1 = triv.direct_sum(can)
            sage: V2 = can.direct_sum(triv)
            sage: hom = V1.hom(V2)
            sage: image, map = hom.image(matrix(K, [[0, 1], [0, 0]]))
            sage: image.isomorphism_to(can) is not None
            True
            sage: image.hom(V2).coordinates_in_h0(map)
            (1, 0)
        """
        dom = self._domain
        cod = self._codomain
        ideals, C_fi = function_field_utility.pseudo_hermite_form(
                dom._ideals,
                f*dom._g_finite,
                False)
        C_inf = function_field_utility.hermite_form_infinite_polymod(
                f*dom._g_infinite,
                False)
        g_fi = C_inf.solve_right(C_fi)
        K = self._function_field
        image = VectorBundle(K, ideals, g_fi, identity_matrix(K, g_fi.ncols()))
        return image, C_inf

    def kernel(self, f):
        r"""
        Return a kernel of global homomorphism ``f`` which is an element of
        `H^0(\mathrm{self})`.

        That is, a vector bundle `V` together with an injective morphism of `V`
        into ``self.domain`` such that the image of `V` in ``self.domain``
        is the kernel of ``f``.

        EXAMPLES ::

            sage: from vector_bundle import trivial_bundle, canonical_bundle
            sage: F.<x> = FunctionField(GF(7))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: triv = trivial_bundle(K)
            sage: can = canonical_bundle(K)
            sage: V1 = triv.direct_sum(can)
            sage: V2 = can.direct_sum(triv)
            sage: hom = V1.hom(V2)
            sage: kernel, map = hom.kernel(matrix(K, [[0, 1], [0, 0]]))
            sage: kernel.isomorphism_to(triv) is not None
            True
            sage: kernel.hom(V1).coordinates_in_h0(map)
            (1, 0)
        """
        dom = self._domain
        cod = self._codomain
        ideals, _, U_fi = function_field_utility.pseudo_hermite_form(
                dom._ideals,
                f*dom._g_finite,
                transformation=True)
        _, U_inf = function_field_utility.hermite_form_infinite_polymod(
                f*dom._g_infinite,
                transformation=True)
        r = f.rank()
        n = f.ncols()
        ideals = ideals[:n-r]
        C_fi = U_fi[:,:n-r]
        C_inf = U_inf[:,:n-r]
        g_fi = C_inf.solve_right(C_fi)
        K = self._function_field
        image = VectorBundle(K, ideals, g_fi, identity_matrix(K, g_fi.ncols()))
        return image, C_inf

    def is_isomorphism(self, f):
        r"""
        Check if f is an isomorphism from ``self.domain()`` to 
        ``self.codomain()``

        EXAMPLES::

            sage: from vector_bundle import atiyah_bundle, canonical_bundle
            sage: F.<x> = FunctionField(GF(7))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: V = atiyah_bundle(K, 2, 0)
            sage: W = atiyah_bundle(K, 2, 0, canonical_bundle(K))
            sage: isom = x^2/(x^2 + 3) * identity_matrix(K, 2)
            sage: V.hom(W).is_isomorphism(isom)
            True
        """
        dual = self.dual()
        return self.is_in_h0(f) and dual.is_in_h0(f**-1)

            
class EndBundle(HomBundle):
    r"""
    Vector bundles representing endomorphism sheaves of vector bundles.

    EXAMPLES::

        sage: from vector_bundle import trivial_bundle, canonical_bundle
        sage: F.<x> = FunctionField(GF(7))
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y^4 - x^-2 - 1)
        sage: triv = trivial_bundle(K)
        sage: can = canonical_bundle(K)
        sage: triv.direct_sum(can).end()
        Endomorphism bundle of Vector bundle of rank 2 over Function field in y defined by y^4 + (6*x^2 + 6)/x^2
    """
    def __init__(self, bundle):
        HomBundle.__init__(self, bundle, bundle)
        self._A = None

    def __repr__(self):
        return "Endomorphism bundle of %s" % (self._domain)

    def global_algebra(self):
        r"""
        Return ``self.h0()`` as a k-algebra in which computations may be done.
        Also return maps to and from the algebra.

        EXAMPLES::

            sage: from vector_bundle import trivial_bundle, canonical_bundle
            sage: F.<x> = FunctionField(GF(7))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^4 - x^-2 - 1)
            sage: triv = trivial_bundle(K)
            sage: can = canonical_bundle(K)
            sage: end = triv.direct_sum(can).end()
            sage: A, to_A, from_A = end.global_algebra(); A
            Finite-dimensional algebra of degree 4 over Finite Field of size 7
            sage: h0 = end.h0()
        """
        if self._A is not None:
            return self._A
        k = self._function_field.constant_base_field()
        category = Algebras(k).FiniteDimensional().WithBasis().Associative()
        basis = self.h0()
        tables = [matrix(k,[self.coordinates_in_h0(b*a) for b in basis])
                  for a in basis]
        algebra = FiniteDimensionalAlgebra(
                k,
                tables,
                assume_associative=True,
                category = category)
        to_a = lambda mat : algebra(self.coordinates_in_h0(mat))
        from_a = lambda a : self.h0_from_vector(a.vector())
        self._A = (algebra, to_a, from_a)
        return algebra, to_a, from_a

    @cached_method
    def _global_algebra_split(self):
        r"""
        Return a splitting of ``self.global_algebra()``

        OUTPUT:

        - ``factors`` -- List of the matrix algebras that are simple
        factors of the semi-simple quotient of self
        inverse. Come with maps to and from ``self.global_algebra()``

        EXAMPLES::

            sage: from vector_bundle import VectorBundle
            sage: from sage.matrix.matrix_space import MatrixSpace
            sage: F.<x> = FunctionField(GF(7))
            sage: L1 = VectorBundle(F, 3 * x.zeros()[0].divisor())
            sage: L2 = VectorBundle(F, -2 * x.poles()[0].divisor())\
            ....:     .direct_sum_repeat(2)
            sage: V = L1.direct_sum(L2)
            sage: T = matrix(
            ....:     F, 3, 3,
            ....:     [2*x, 4, x+1, 4*x, 4*x+6, 5*x+6, 5*x+2, 5*x+3, 2*x+6])
            sage: V = V.apply_isomorphism(T)
            sage: End = V.end()
            sage: _, _, from_A = End.global_algebra()
            sage: S, factors = End._global_algebra_split()
            sage: len(factors)
            2
            sage: deg_1_index = [f.M.nrows() for f in factors].index(1)
            sage: deg_2_index = 1 - deg_1_index
            sage: f = factors[deg_1_index]
            sage: T^-1 * from_A(S[2](f.from_M(identity_matrix(GF(7),1)))) * T 
            [1 0 0]
            [0 0 0]
            [0 0 0]
            sage: f = factors[deg_2_index]
            sage: T^-1 * from_A(S[2](f.from_M(identity_matrix(GF(7),2)))) * T 
            [0 0 0]
            [0 1 0]
            [0 0 1]
        """
        A, _, _ = self.global_algebra()
        return algebras.full_split(A)
