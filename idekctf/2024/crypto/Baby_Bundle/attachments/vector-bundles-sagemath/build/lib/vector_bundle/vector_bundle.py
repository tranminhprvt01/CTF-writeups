r"""
This module implements algebraic algorithms for manipulating vector bundles 
as pairs of lattices over its function field. Follows the algorithmic methods
discussed in [Mon24]_

EXAMPLES ::

    sage: from vector_bundle import VectorBundle
    sage: F.<x> = FunctionField(GF(3))
    sage: R.<y> = F[]
    sage: K.<y> = F.extension(y^2 - x^3 - x)
    sage: order = K.maximal_order()
    sage: ideals = [K.places_finite()[0].prime_ideal()^-1, order.ideal(1)]
    sage: g_finite = identity_matrix(K,2)
    sage: g_infinite = matrix(K,[[1, 0], [0, 1/x^2*y]])
    sage: V = VectorBundle(K, ideals, g_finite, g_infinite); V
    Vector bundle of rank 2 over Function field in y defined by y^2 + 2*x^3 + 2*x

We can compute a basis of the space of global sections of ``V``::

    sage: h0 = V.h0(); h0
    [(1, 0)]

We can also compute a basis of the `H^1` group of ``V``. First, a basis of its
dual is computed::

    sage: h1_dual, _ = V.h1_dual(); h1_dual
    [[0 1]]

Then, we compute a representent of a linear form over ``h1_dual``::

    sage: V.h1_element([1])
    [0, (x/(x^2 + 1))*y]

We can verify the Riemann-Roch theorem::

    sage: len(h0) - len(h1_dual) == V.degree() + V.rank()*(1 - K.genus())
    True

REFERENCES:

.. [At57] M. F. Atiyah
   *Vector Bundles on Elliptic Curves*
   Proc. Lond. Math. Soc.
   3(1):414-452, 1957

.. [Mon24] M. Montessinos
   *Algebraic algorithms for vector bundles over algebraic curves*
   In preparation

.. [Sav08] V. Savin
   *Algebraic-Geometric Codes from Vector Bundles and their Decoding*

.. [NR69] M. S. Narasimhan and S. Ramanan
   *Moduli of vector bundles on a compact Riemann surface*
   Ann. of Math. 89(1):14-51, 1969

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

from copy import copy
from sage.misc.cachefunc import cached_method
from sage.structure.sage_object import SageObject
from sage.misc.misc_c import prod
from sage.arith.functions import lcm
from sage.arith.misc import integer_ceil
from sage.functions.log import logb, log
from sage.matrix.constructor import matrix
from sage.structure.element import Matrix
from sage.matrix.special import (block_matrix, elementary_matrix,
                                identity_matrix, diagonal_matrix,
                                zero_matrix, block_diagonal_matrix)
from sage.matrix.matrix_space import MatrixSpace
from sage.rings.function_field.ideal import FunctionFieldIdeal
from sage.rings.function_field.function_field_rational\
        import RationalFunctionField
from sage.rings.function_field.order_rational\
        import FunctionFieldMaximalOrderInfinite_rational
from sage.modules.free_module_element import vector
from sage.schemes.projective.projective_space import ProjectiveSpace
from . import function_field_utility
from . import ext_group 


class VectorBundle(SageObject):
    r"""
    A vector bundle defined over a normal curve with function field K.

    If ``g_finite`` and ``g_infinite`` are None and ideals is a divisor, the line
    bundle `L(D)` is returned.

    If the constructed vector bundle is to have rank one, ``ideals`` may be an
    ideal instead of a list. Likewise, ``g_finite`` and ``g_infinite`` can be 
    elements of `K` rather that matrices of size `1 \times 1`.

    INPUT:

    - ``function_field`` -- FunctionField; the function field of the bundle

    - ``ideals`` -- list of coefficient ideals of the finite part of the bundle 

    - ``g_finite`` -- matrix; a basis of the finite part of the bundle

    - ``g_infinite`` -- matrix; a basis of the infinite part of the bundle

    EXAMPLES ::

        sage: from vector_bundle import VectorBundle
        sage: F.<x> = FunctionField(GF(3))
        sage: VectorBundle(F,x.poles()[0].divisor())
        Vector bundle of rank 1 over Rational function field in x over Finite Field of size 3
        sage: R.<y> = F[]
        sage: K.<y> = F.extension(y^2 - x^3 - x)
        sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
        sage: g_finite = matrix([[1, x], [y, 2]])
        sage: g_infinite = matrix([[x, y], [x + y, 1]])
        sage: VectorBundle(K, ideals, g_finite, g_infinite)
        Vector bundle of rank 2 over Function field in y defined by y^2 + 2*x^3 + 2*x

    A line bundle may be defined without using lists and matrices::

        sage: VectorBundle(K, K.maximal_order().ideal(1), 1, 1)
        Vector bundle of rank 1 over Function field in y defined by y^2 + 2*x^3 + 2*x

    It may also be defined using a divisor::

        sage: VectorBundle(K, K.one().divisor())
        Vector bundle of rank 1 over Function field in y defined by y^2 + 2*x^3 + 2*x
    """

    def __init__(self,function_field, ideals,g_finite=None,g_infinite=None, check=True):
        if g_finite is None or g_infinite is None:
            self._line_bundle_from_divisor(function_field, ideals, check=check)
        else:
            self._vector_bundle_from_data(function_field, ideals,
                                        g_finite,g_infinite, check)
        self._h0 = None
        self._h0_matrix = None
        self._h0_Kp = None
        self._h0_vs = None

    def __hash__(self):
        return hash((tuple(self._ideals),
                     tuple(self._g_finite.list()),
                     tuple(self._g_infinite.list())))

    def __eq__(self,other):
       return (self._ideals == other._ideals
               and self._g_finite == other._g_finite
               and self._g_infinite == other._g_infinite)

    def _neq_(self, other):
        return not self ==  other

    def _repr_(self):
        return "Vector bundle of rank %s over %s" % (
            self.rank(),
            self._function_field,
            )

    def _line_bundle_from_divisor(self,function_field,divisor, check=True):
        r"""
        Build a line bundle from a divisor
        """
        if check:
            if not function_field == divisor.parent().function_field():
                raise ValueError('The divisor should be defined over the '
                                 + 'function field.')
        self._function_field = function_field
        couples = divisor.list()
        finite_part = [c for c in couples if not c[0].is_infinite_place()]
        self._ideals = [prod([place.prime_ideal()**-mult
                              for place,mult in finite_part],
                             self._function_field.maximal_order().ideal(1))]
        self._g_finite = matrix(function_field,[[1]])
        infinite_places = function_field_utility.all_infinite_places(
                function_field)
        pi = function_field_utility.infinite_approximation(
                infinite_places,
                [1-divisor.multiplicity(place) for place in infinite_places],
                [place.local_uniformizer()**-divisor.multiplicity(place)
                 for place in infinite_places])
        self._g_infinite = matrix(function_field,[[pi]])

    def _vector_bundle_from_data(self,function_field,
                                 ideals,g_finite,g_infinite, check=True):
        r"""
        Construct a vector bundle from data.
        """
        if not isinstance(ideals,list):
            ideals=[ideals]
        if not isinstance(g_finite,Matrix):
            if isinstance(g_finite,list):
                g_finite = matrix(g_finite).transpose()
            else:
                g_finite = matrix([[g_finite]])
        if not isinstance(g_infinite,Matrix):
            if isinstance(g_finite,list):
                g_infinite = matrix(g_infinite).transpose()
            else:
                g_infinite = matrix([[g_infinite]])
        g_finite.change_ring(function_field)
        g_infinite.change_ring(function_field)
        r = len(ideals)
        if check:
            if (g_finite.nrows() != r
                or g_finite.ncols() != r
                or g_infinite.nrows() != r
                or g_infinite.ncols() != r):
                    raise ValueError('The length of the ideal list must equal'
                                     + ' the size of the basis matrices')
            if not g_finite.is_invertible() or not g_infinite.is_invertible():
                raise ValueError('The basis matrices must be invertible')
            if not all([isinstance(I,FunctionFieldIdeal)
                        for I in ideals]):
                raise TypeError('The second argument must be a list of \
                                FunctionFieldIdeals.')
            if not all([I.base_ring() == function_field.maximal_order()
                        for I in ideals]):
                raise ValueError('All ideals must have the maximal order of\
                                 function_field as base ring.')
        self._function_field = function_field
        self._ideals = ideals
        self._g_finite = g_finite
        self._g_infinite = g_infinite

    def function_field(self):
        r"""
        Return the function field of the vector bundle

        EXAMPLES ::

            sage: from vector_bundle import trivial_bundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: V = trivial_bundle(K)
            sage: V.function_field()
            Function field in y defined by y^2 + 2*x^3 + 2*x
        """
        return self._function_field

    def coefficient_ideals(self):
        r"""
        Return the coefficient ideals of the finite part of self.

        EXAMPLES :: 

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1, x], [2, y]])
            sage: g_infinite = matrix([[x, 1], [2, y]])
            sage: V = VectorBundle(K, ideals, g_finite, g_infinite)
            sage: Is = V.coefficient_ideals()
            sage: Is == [P.prime_ideal() for P in K.places_finite()[:2]]
            True
        """
        return copy(self._ideals)

    def basis_finite(self):
        r"""
        Return the basis vectors of the finite part of self.

        The basis elements may not be in the corresponding lattice over the
        finite maximal order: the lattice may not be free and one must account
        for the coefficient ideals.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1, x], [2, y]])
            sage: g_infinite = matrix([[x, 1], [2, y]])
            sage: V = VectorBundle(K, ideals, g_finite, g_infinite)
            sage: V.basis_finite()
            [(1, 2), (x, y)]
        """
        return [vector(self._g_finite[:, j]) for j in range(self.rank())]

    def basis_infinite(self):
        r"""
        Return the basis vectors of the infinite part of self.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1, x], [2, y]])
            sage: g_infinite = matrix([[x, 1], [2, y]])
            sage: V = VectorBundle(K, ideals, g_finite, g_infinite)
            sage: V.basis_infinite()
            [(x, 2), (1, y)]
        """
        return [vector(self._g_infinite[:, j]) for j in range(self.rank())]

    def basis_local(self,place):
        r"""
        Return a local basis of self at prime.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1, x], [2, y]])
            sage: g_infinite = matrix([[x, 1], [2, y]])
            sage: V = VectorBundle(K, ideals, g_finite, g_infinite)
            sage: V.basis_local(K.places_finite()[0])
            [(x, 2*x), (x, y)]
        """
        if place.is_infinite_place():
            return self._g_infinite
        pi = place.local_uniformizer()
        return [(pi**self._ideals[j].divisor().valuation(place))
                * vector(self._g_finite[:, j])
                for j in range(self.rank())]

    def rank(self):
        r"""
        Return the rank of a vector bundle.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: O = K.maximal_order()
            sage: V = VectorBundle(K, O.ideal(1), x, y)
            sage: V.rank()
            1
        """
        return len(self._ideals)

    @cached_method
    def determinant(self):
        r"""
        Return the determinant bundle.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1, x], [2, y]])
            sage: g_infinite = matrix([[x, 1], [2, y]])
            sage: V = VectorBundle(K, ideals, g_finite, g_infinite)
            sage: d = V.determinant()
            sage: d._ideals
            [Ideal (x) of Maximal order of Function field in y defined by y^2 + x + 2]
            sage: d._g_finite
            [y + x]
            sage: d._g_infinite
            [x*y + 1]
        """
        if self.rank() == 1:
            return self
        O = self._function_field.maximal_order()
        I = prod(self._ideals)
        determinant_finite = self._g_finite.determinant()
        determinant_infinite = self._g_infinite.determinant()
        return VectorBundle(self._function_field,
                            I,
                            determinant_finite,
                            determinant_infinite,
                            check=False)

    def degree(self):
        r"""
        Returns the degree of the vector bundle.

        This is defined as the degree of the divisor of the determinant bundle.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1, x], [2, y]])
            sage: g_infinite = matrix([[x, 1], [2, y]])
            sage: V = VectorBundle(K, ideals, g_finite, g_infinite)
            sage: V.degree()
            -1
        """
        if self.rank() > 1:
            return self.determinant().degree()
        degree_ideal = self._ideals[0].divisor().degree()
        order_finite = self._function_field.maximal_order()
        order_infinite = self._function_field.maximal_order_infinite()
        divisor_finite = order_finite.ideal(self._g_finite[0,0]).divisor()
        divisor_infinite = order_infinite.ideal(self._g_infinite[0,0]).divisor()
        return -(degree_ideal
                 + divisor_finite.degree()
                 + divisor_infinite.degree())

    def slope(self):
        r"""
        Return the slop of the vector bundle.

        The slope is the ratio rank/degree

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: from vector_bundle import trivial_bundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2-x^3-x)
            sage: E = VectorBundle(K, K.places_infinite()[0].divisor())
            sage: V = E.non_trivial_extension(trivial_bundle(K))
            sage: V.slope()
            1/2
        """
        return self.degree()/self.rank()

    def is_locally_trivial(self,place):
        r"""
        Check if the vector bundle is the trivial lattice at place ``place``

        EXAMPLES ::
        
            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(7))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: L1 = VectorBundle(K, K.places_finite()[0].divisor())
            sage: L2 = VectorBundle(K, K.places_finite()[1].divisor())
            sage: V = L1.direct_sum(L2)
            sage: V.is_locally_trivial(K.places_finite()[0])
            False
            sage: V.is_locally_trivial(K.places_finite()[2])
            True
            sage: V.is_locally_trivial(K.places_infinite()[0])
            True
            sage: L = VectorBundle(K,K.places_infinite()[0].divisor())
            sage: L.is_locally_trivial(K.places_infinite()[0])
            False
        """
        basis = self.basis_local(place)
        mat = matrix(basis)
        return (all([c.valuation(place) >= 0 for c in mat.list()])
                and mat.determinant().valuation(place) == 0)

    def hom(self,other):
        r"""
        Returns the hom bundle ``Hom(self,other)``

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
            sage: V2 = VectorBundle(K, O.ideal(1), 1, x^2)
            sage: V = V1.hom(V2)
            sage: V.rank() == V1.rank() * V2.rank()
            True
            sage: V.degree() == V2.degree()*V1.rank() - V1.degree()*V2.rank()
            True
        """
        from . import hom_bundle
        return hom_bundle.HomBundle(self,other)

    def end(self):
        r"""
        Return the hom bundle of endomorphisms of ``self``.

        Examples ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: L1 = VectorBundle(F, x.zeros()[0].divisor())
            sage: L2 = VectorBundle(F, x.poles()[0].divisor())
            sage: E = L1.direct_sum(L2).end(); E.h0()
            [
            [1 0]  [0 0]  [  0 1/x]  [0 0]
            [0 0], [x 0], [  0   0], [0 1]
            ]
        """
        from . import hom_bundle
        return hom_bundle.EndBundle(self)

    def dual(self):
        r"""
        Returns the dual vector bundle of ``self``.

        EXAMPLES ::
        
            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1, x], [2, y]])
            sage: g_infinite = matrix([[x, 1], [2, y]])
            sage: V = VectorBundle(K, ideals, g_finite, g_infinite)
            sage: Vd = V.dual()
            sage: Vd.rank() == V.rank()
            True
            sage: Vd.degree() == -V.degree()
            True
        """
        from . import constructions
        return self.hom(constructions.trivial_bundle(self._function_field))

    def direct_sum(self,other):
        r"""
        Returns the direct sum of two vector bundles

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
            sage: V2 = VectorBundle(K, O.ideal(1), 1, x^2)
            sage: V = V1.direct_sum(V2)
            sage: V.rank() == V1.rank() + V2.rank()
            True
            sage: V.degree() == V1.degree() + V2.degree()
            True
        """
        ideals = self._ideals + other._ideals
        g_finite = block_matrix([[self._g_finite,0],[0,other._g_finite]])
        g_infinite = block_matrix([[self._g_infinite,0],[0,other._g_infinite]])
        return VectorBundle(self._function_field, ideals,
                            g_finite, g_infinite, check=False)

    def _direct_sum_rec(self,acc,n):
        r"""
        Accumulator function for ``direct_sum_repeat``.
        """
        if n < 0:
            raise ValueError('n should be nonnegative')
        elif n == 0:
            return acc
        return self._direct_sum_rec(self.direct_sum(acc), n-1)

    def direct_sum_repeat(self,n):
        r"""
        Return the direct sum of ``n`` copies of ``self``.

        EXAMPLES ::
            
            sage: from vector_bundle import trivial_bundle
            sage: F.<x> = FunctionField(GF(3))
            sage: L = trivial_bundle(F)
            sage: V = L.direct_sum_repeat(3)
            sage: V.rank()
            3
            sage: V.degree()
            0
            sage: V.h0()
            [(1, 0, 0), (0, 1, 0), (0, 0, 1)]
        """
        if n <= 0:
            raise ValueError('n should be positive')
        return self._direct_sum_rec(self,n-1)

    def tensor_product(self,other):
        r"""
        Returns the tensor product of two vector bundles

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
            sage: V2 = VectorBundle(K, O.ideal(1), 1, x^2)
            sage: V = V1.tensor_product(V2)
            sage: V.rank() == V1.rank() * V2.rank()
            True
            sage: V.degree() == V1.degree()*V2.rank() + V2.degree()*V1.rank()
            True
        """
        ideals = [I * J for I in self._ideals for J in other._ideals]
        g_finite = self._g_finite.tensor_product(other._g_finite)
        g_infinite = self._g_infinite.tensor_product(other._g_infinite)
        return VectorBundle(self._function_field, ideals,
                            g_finite, g_infinite, check=False)

    def _tensor_power_aux(self,acc,n):
        r"""
        Auxiliary recursive function for ``tensor_power``
        """
        if n < 0:
            raise ValueError('n should be nonnegative')
        elif n == 0:
            return acc
        return self._tensor_power_aux(self.tensor_product(acc),n-1)

    def tensor_power(self,n):
        r"""
        Return the n-th tensor power of ``self``

        EXAMPLES ::
        
            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: L = VectorBundle(F, x.poles()[0].divisor())
            sage: E = L.tensor_power(3)
            sage: E.rank()
            1
            sage: E.degree()
            3
            sage: E.h0()
            [(1), (x), (x^2), (x^3)]
        """
        if n <= 0:
            raise ValueError('n should be positive')
        return self._tensor_power_aux(self,n-1)


    def conorm(self,K):
        r"""
        Return the conorm of the vector bundle over an extension of its base
        
        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: ideals = [P.prime_ideal() for P in F.places_finite()[:2]]
            sage: g_finite = matrix([[1, x], [2, x]])
            sage: g_infinite = matrix([[x, 1], [2, x]])
            sage: V = VectorBundle(F, ideals, g_finite, g_infinite)
            sage: VK = V.conorm(K)
            sage: VK.rank()
            2
            sage: VK.degree() == K.degree() * V.degree()
            True
        """
        O = K.maximal_order()
        ideals = [O.ideal(I.gens()) for I in self._ideals]
        return VectorBundle(K, ideals,self._g_finite,
                            self._g_infinite, check=False)

    def restriction(self):
        r"""
        Return the Weil restriction of the vector bundle over the base field of
        ``self._function_field``

        As a vector bundle is seen as a pair of lattices, the Weil restriction
        of a bundle is the pair of lattices seen above the maximal orders of
        the base field. Equivalently, if the field extension K in L corresponds
        to a morphism of curves f from Y to X, the restriction is the direct
        image under f.
        
        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 + x + 2)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1, x], [2, y]])
            sage: g_infinite = matrix([[x, 1], [2, y]])
            sage: V = VectorBundle(K, ideals, g_finite, g_infinite)
            sage: VF = V.restriction()
            sage: VF._ideals
            [Ideal (1) of Maximal order of Rational function field in x over Finite Field of size 3,
            Ideal (1) of Maximal order of Rational function field in x over Finite Field of size 3,
            Ideal (1) of Maximal order of Rational function field in x over Finite Field of size 3,
            Ideal (1) of Maximal order of Rational function field in x over Finite Field of size 3]
            sage: VF._g_finite
            [      x       1     x^2     2*x]
            [      0       1       0       x]
            [    2*x       2       0 2*x + 1]
            [      0       2       x       2]
            sage: VF._g_infinite
            [          x           0           1           0]
            [          0           1           0         1/x]
            [          2           0           0 (2*x + 1)/x]
            [          0         2/x           1           0]
        """
        F = self._function_field.base_field()
        trivial_ideal = F.maximal_order().ideal(1)
        ideals = [trivial_ideal for _ in range(self._function_field.degree() * self.rank())]
        g_finite = matrix([vector(c*self._g_finite[:, i]) for i,I in enumerate(self._ideals)
                           for c in I.gens_over_base()])
        g_finite = matrix([sum([a.list() for a in collumn],[])
                           for collumn in g_finite]).transpose()
        gen_infinite = self._function_field.maximal_order_infinite().ideal(1)\
                .gens_over_base()
        g_infinite = matrix([vector(c*self._g_infinite[:, i]) for i in range(self.rank())
                             for c in gen_infinite])
        g_infinite = matrix([sum([a.list() for a in collumn],[])
                           for collumn in g_infinite]).transpose()
        return VectorBundle(F, ideals,g_finite,
                            g_infinite, check=False)

    def _h0_rational(self):
        r"""
        Returns a k-basis of self.

        self.function_field must be a rational function field.
        Elements of ``self._ideals`` are assumed to be trivial.
        Some lines of code are borrowed from the implementation of
        ``sage.rings.function_field.divisor.FunctionFieldDivisor._basis``

        ALGORITHM:

        The basis reduction algorithm used in [Len84]

        TODO:

        Try more recent algorithms such as [GSSV12]
        Implement Popov form normalization to get a normalized h0 basis.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: ideals = [F.maximal_order().ideal(1)] * 2
            sage: g_finite = matrix([[x^-5, x^-1], [2 + x^-2, 1]])
            sage: g_infinite = matrix([[2*x + x^-2, 2], [x^3 + 2*x^-1, 1]])
            sage: V = VectorBundle(F, ideals, g_finite, g_infinite)
            sage: V.degree()
            4
            sage: h0 = V._h0_rational(); len(h0)
            6
            sage: O_finite = F.maximal_order()
            sage: O_infinite = F.maximal_order_infinite()
            sage: all([all([c in O_finite for c in g_finite**-1 * v]) for v in h0])
            True
            sage: all([all([c in O_infinite for c in g_infinite**-1 * v]) for v in h0])
            True
        """
        mat = self._g_infinite**-1 * self._g_finite
        mat_0 = copy(mat)
        den =  lcm([e.denominator() for e in mat.list()])
        R = den.parent()
        one = R.one()
        mat = matrix(R,self.rank(),[e.numerator() for e in (den*mat).list()])
        mat = mat.popov_form(row_wise=False)
        mat /= den
        basis = []
        for i in range(self.rank()):
            for p in range(min([c.denominator().degree()
                                - c.numerator().degree()
                                for c in mat[:, i].list() if c != 0]) + 1):
                basis.append(self._g_infinite * vector(one.shift(p)*mat[:, i]))
        return basis

    def h0(self):
        r"""
        Returns a basis of the 0th cohomology group of ``self``

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1,1 / (x**5 + y)],[2, y]])
            sage: g_infinite = matrix([[x, 1], [2, y**3]])
            sage: V = VectorBundle(K, ideals, g_finite, g_infinite)
            sage: V.degree()
            6
            sage: h0 = V.h0(); len(h0)
            6
            sage: all([all([c in ideals[i] for i,c in enumerate(list(g_finite**-1 * v))]) for v in h0])
            True
            sage: O_infinity = K.maximal_order_infinite()
            sage: all([all([c in O_infinity for c in g_infinite**-1 * v]) for v in h0])
            True

        TESTS ::

            sage: from vector_bundle import VectorBundle
            sage: from vector_bundle import canonical_bundle
            sage: F.<x> = FunctionField(GF(3))
            sage: ideals = [F.maximal_order().ideal(x), F.maximal_order().ideal(1 / (1+x^3))]
            sage: g_finite = matrix([[x^-5, x^-1], [2 + x^-2, 1]])
            sage: g_infinite = matrix([[2*x + x^-2, 2], [x^3 + 2*x^-1, 1]])
            sage: V = VectorBundle(F, ideals, g_finite, g_infinite)
            sage: V.degree()
            6
            sage: h0 = V.h0(); len(h0)
            8
            sage: all([all([c in ideals[i] for i,c in enumerate(list(g_finite**-1 * v))]) for v in h0])
            True
            sage: O_infinite = F.maximal_order_infinite()
            sage: all([all([c in O_infinite for c in g_infinite**-1 * v]) for v in h0])
            True
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^4 - x**-2 - 1)
            sage: L = canonical_bundle(K)
            sage: len(L.h0())
            1
        """
        if self._h0 is not None:
            return self._h0
        if isinstance(self._function_field,RationalFunctionField):
            #Compute restriction to normalize the coefficient ideals.
            return self.restriction()._h0_rational()
        res = self.restriction()
        h0_res = res.h0()
        h0 = []
        y = self._function_field.gen()
        deg = self._function_field.degree()
        for v in h0_res:
                h0.append(vector([sum([y**j * v[i*deg + j]
                                       for j in range(deg)])
                                  for i in range(self.rank())]))
        self._h0 = h0
        return h0

    @cached_method
    def h1_dual(self):
        r"""
        Return the dual of the 1st cohomology group of the vector bundle.
        By Serre duality, this is the 0th cohomology group of
        ``canonical_bundle(self._function_field).tensor_product(self.dual())``

        OUTPUT:

        - a basis of the dual of the h1 of self
        - the hom bundle whose h0 has basis the first output

        EXAMPLES ::

            sage: from vector_bundle import trivial_bundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: L = trivial_bundle(K)
            sage: L.h1_dual()
            ([[1]],
            Homomorphism bundle from Vector bundle of rank 1 over Function field in y defined by y^2 + 2*x^3 + 2*x to Vector bundle of rank 1 over Function field in y defined by y^2 + 2*x^3 + 2*x)
        """
        from . import constructions
        line_bundle = constructions.canonical_bundle(self._function_field)
        vector_bundle = self.hom(line_bundle)
        return vector_bundle.h0(), vector_bundle

    def h1_dimension(self):
        r"""
        Return the dimension of the 1st cohomology group of the vector bundle.

        EXAMPLES ::

            sage: from vector_bundle import trivial_bundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: L = trivial_bundle(K)
            sage: L.h1_dimension()
            1
            sage: K.genus()
            1
        """
        h1,_ = self.h1_dual()
        return len(h1)

    def h1_element(self,form=None):
        r"""
        Represent a linear form over ``self.h1_dual()`` under Serre duality.
        
        INPUT:

        - ``form`` -- vector of elements of self._function_field.constant_base_field() representing a linear form over self.h1_dual(). (default: [1,0,...,0])

        OUTPUT:

        - ''res'' -- vector of elements of K such that the corresponding infinite répartition vectorcorresponds to form under Serre duality with respect to ``safe_uniformizers(self._function_field)[0].differential()``.

        EXAMPLES ::
            
            sage: from vector_bundle import trivial_bundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: triv = trivial_bundle(K)
            sage: triv.h1_element([1])
            [(x/(x^2 + 1))*y]
        """
        K = self._function_field
        h1_dual, h1_dual_bundle = self.h1_dual()
        s = len(h1_dual)
        if form is None:
            form = [1] + [0] * (s-1)
        r = self.rank()
        places = function_field_utility.all_infinite_places(K)
        pi_0 = function_field_utility.safe_uniformizers(K)[0]
        place_0 = places[0]
        k,from_k,to_k = place_0.residue_field()
        form = vector([function_field_utility.invert_trace(
            k, K.constant_base_field(), c) for c in form])
        dual_matrix = matrix([h1_dual_bundle._matrix_to_vector(mat)
                              for mat in h1_dual]).transpose()
        zero_rows = [i for i, row in enumerate(dual_matrix) if row == 0]
        n_matrix, _, _  = function_field_utility.full_rank_matrix_in_completion(
                dual_matrix,
                place_0,
                pi_0)
        ell = n_matrix.nrows() // dual_matrix.nrows()
        ell_pow = k.cardinality() ** integer_ceil(logb(ell,k.cardinality()))
        res = n_matrix.solve_left(form)
        min_vals = [[min([c.valuation(place) for c in dual_matrix.list()])] 
                     for place in places]
        pi = function_field_utility.infinite_approximation(
                places,
                [1] + [integer_ceil(-min_val/ell) for min_val in min_vals[1:]],
                [1] + [0]*(len(places)-1))**ell_pow
        res = [function_field_utility.infinite_approximation(
            places,
            [1] + [0]*(len(places)-1),
            [a] + [0]*(len(places)-1))**ell_pow
               for a in res]
        min_vals_0 = [0 if i in zero_rows
                      else min([dual_matrix[i,j].valuation(place_0) 
                                for j in range(s)])
                      for i in range(r)]
        return [pi
                * pi_0**(-min_vals_0[i]-1)
                * sum([pi_0**(-j) * res[i*ell + j] for j in range(ell)])
                if not i in zero_rows else 0
                for i in range(r)]

    @cached_method
    def extension_group(self, other, precompute_basis=False):
        r"""
        Return the extension group of ``self`` by ``other``.
        If ``precompute_basis`` is set to ``True``, a basis of the extension
        group is precomputed. Extensions may be constructed without using
        a precomputed basis, but each construction is a bit costlier this way.
        You should precompute a basis if you are planning to compute
        an number of extensions larger than the dimension of the ext group.

        EXAMPLES::

            sage: from vector_bundle import trivial_bundle, canonical_bundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: trivial_bundle(K).extension_group(canonical_bundle(K))
            Extension group of Vector bundle of rank 1 over Function field in 
            y defined by y^2 + 2*x^3 + 2*x by Vector bundle of rank 1 over 
            Function field in y defined by y^2 + 2*x^3 + 2*x.
        """
        return ext_group.ExtGroup(self, other, precompute_basis)

    def non_trivial_extension(self, other):
        r"""
        Return any nontrivial extension of self by other.

        EXAMPLES::

            sage: from vector_bundle import trivial_bundle, canonical_bundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: triv = trivial_bundle(K)
            sage: can = canonical_bundle(K)
            sage: V = triv.non_trivial_extension(can)
            sage: V.rank()
            2
            sage: V.degree()
            0
            sage: V.h0()
            [(1, 0)]
            sage: V.end().h0()
            [
            [0 1]  [1 0]
            [0 0], [0 1]
            ]
        """
        ext_group = self.extension_group(other)
        return ext_group.extension()
        
    def extension_by_global_sections(self):
        r"""
        Return the canonical extension of ``self`` by `\omega^s` where `\omega` is the
        canonical line bundle and `s` is `dim(H^0(\mathrm{self}))`.

        This extension is defined in [At57]_ for elliptic curves, but the
        constructions generalises to arbitrary genus if one replaces the
        trivial line bundle with a canonical line bundle.

        EXAMPLES ::

            sage: from vector_bundle import trivial_bundle, VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: T = trivial_bundle(K)
            sage: E = T.extension_by_global_sections()
            sage: E.rank()
            2
            sage: E.end().h0()
            [
            [0 1]  [1 0]
            [0 0], [0 1]
            ]
            sage: L = VectorBundle(K,K.places_infinite()[0].divisor())
            sage: E = (E.tensor_product(L)).extension_by_global_sections()
            sage: E.rank()
            4
            sage: E.degree()
            2
            sage: E.hom(E).h0()
            [
            [0 1 0 0]  [1 0 0 0]
            [0 0 0 0]  [0 1 0 0]
            [0 0 0 1]  [0 0 1 0]
            [0 0 0 0], [0 0 0 1]
            ]
        """
        from . import constructions
        h0 = self.h0()
        s = len(h0)
        ohm = constructions.canonical_bundle(self._function_field)\
                .direct_sum_repeat(s)
        ext_group = self.extension_group(ohm)
        ext_dual = ext_group.dual_bundle()
        canonical_ext = matrix(h0).transpose()
        form = ext_dual.coordinates_in_h0(canonical_ext)
        return ext_group.extension(form)

    def h0_from_vector(self, v):
        r"""
        Return an element of `H^0(\mathrm{self})` from a vector of coordinates
        in the basis given by ``self.h0()``

        EXAMPLES ::
            
            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(7))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1,1 / (x**5 + y)],[2, y]])
            sage: g_infinite = matrix([[x, 1], [2, y**3]])
            sage: V = VectorBundle(K, ideals, g_finite, g_infinite)
            sage: h0 = V.h0()
            sage: v = vector(list(range(6)))
            sage: V.coordinates_in_h0(V.h0_from_vector(v))
            (0, 1, 2, 3, 4, 5)
        """
        return sum([a*e for a, e in zip(v, self.h0())])
                            
    def coordinates_in_h0(self, f, check=True):
        r"""
        Return a vector of coordinates of ``f`` in the basis returned
        by ``self.h0()``

        If ``check`` is ``True``, it is check whether ``f`` actually lies in the 
        `H^0` space, and None is output if ``f`` is not in `H^0`. If ``check``
        is set to ``False`` the result may be garbage.

        EXAMPLES ::
            
            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(7))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1,1 / (x**5 + y)],[2, y]])
            sage: g_infinite = matrix([[x, 1], [2, y**3]])
            sage: V = VectorBundle(K, ideals, g_finite, g_infinite)
            sage: h0 = V.h0()
            sage: v = sum([i*e for i, e in enumerate(h0)])
            sage: V.coordinates_in_h0(v)
            (0, 1, 2, 3, 4, 5)
        """
        if self._h0_matrix is None:
            mat = matrix(self._function_field, self.h0()).transpose()
            self._h0_matrix, self._h0_Kp, self._h0_vs =\
                    function_field_utility.full_rank_matrix_in_completion(mat)
        ell = self._h0_matrix.nrows() // self.rank()
        series = [self._h0_Kp(c) for c in f]
        v = vector(sum([[s.coefficient(val + j) for j in range(ell)]
                        for s, val in zip(series, self._h0_vs)],[]))
        res = self._h0_matrix.solve_right(v)
        if not check or self.h0_from_vector(res) == f:
            return res 
        return None

    def is_in_h0(self, v):
        r"""
        Check if vector ``v`` with coefficients in 
        ``self.function_field()`` lies in the `k`-vector space spanned
        by the output of ``self.h0()``

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(7))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: ideals = [P.prime_ideal() for P in K.places_finite()[:2]]
            sage: g_finite = matrix([[1,1 / (x**5 + y)],[2, y]])
            sage: g_infinite = matrix([[x, 1], [2, y**3]])
            sage: V = VectorBundle(K, ideals, g_finite, g_infinite)
            sage: V.is_in_h0(V.h0_from_vector(vector(list(range(6)))))
            True
            sage: V.is_in_h0(vector([x^i for i in range(6)]))
            False
        """
        if self.coordinates_in_h0(v) is None:
            return False
        return True

    def _isomorphism_to_large_field(self, other, tries=1):
        r"""
        Return an isomorphism from self to other if it exists and None otherwise.

        May fail to find an isomorphism with probability less than 
        `(\frac{s}{|k|})^\mathrm{tries}`, where k is the constant field and
        s is ``len(self.hom(other).h0())``. This is only usefule if `k` has
        cardinality larger than ``len(self.end().h0())``.
        """
        Hom1 = self.hom(other)
        hom1 = Hom1.h0()
        hom2 = Hom1.dual().h0()
        End = self.end()
        end = End.h0()
        s = len(hom1)
        if s != len(hom2) or s != len(end):
            return None
        k = self.function_field().constant_base_field()
        for _ in range(tries):
            v = vector([k.random_element() for _ in range(s)])
            P = Hom1.h0_from_vector(v)
            mat = matrix([End.coordinates_in_h0(P*Q) for Q in hom2])
            if mat.is_unit():
                return P

    def _isomorphism_indecomposable(self, other):
        r"""
        Return an isomorphism from self to other if it exists.
        Assumes that self is indecomposable.

        TESTS::

            sage: from vector_bundle import atiyah_bundle, canonical_bundle
            sage: F.<x> = FunctionField(GF(7))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: V = atiyah_bundle(K, 2, 0)
            sage: W = atiyah_bundle(K, 2, 0,canonical_bundle(K))
            sage: isom = V._isomorphism_indecomposable(W)
            sage: isom is not None
            True
            sage: hom_1 = V.hom(W)
            sage: hom_2 = W.hom(V)
            sage: hom_1.is_in_h0(isom)
            True
            sage: hom_2.is_in_h0(isom^-1)
            True
        """
        r = self.rank()
        if other.rank() != r:
            return None
        V = self.direct_sum(other)
        End = V.end()
        A, to_A, from_A = End.global_algebra()
        (S, to_S, from_S), factors = End._global_algebra_split()
        if len(factors) > 1:
            return None
        split = factors[0]
        if split.M.nrows() != 2:
            return None
        K = self._function_field
        id_self = split.to_M(to_S(to_A(
            diagonal_matrix(K, [1]*r + [0]*r))))
        im_self = id_self.transpose().echelon_form().rows()
        im_self = [r for r in im_self if not r.is_zero()]
        id_other = split.to_M(to_S(to_A(
            diagonal_matrix(K, [0]*r + [1]*r))))
        im_other = id_other.transpose().echelon_form().rows()
        im_other = [r for r in im_other if not r.is_zero()]
        P = matrix(im_self + im_other).transpose()
        F = split._K
        s = split._n // 2
        id_s = identity_matrix(F, s)
        zero_mat = zero_matrix(F, s)
        isom = P * block_matrix([[zero_mat, zero_mat], [id_s, zero_mat]]) * P**-1
        isom = from_A(from_S(split.from_M(isom)))
        return isom[r:,:r]

    def _indecomposable_power_split(self):
        r"""
        Check if self is a direct sum of copies of an indecomposable bundle.
        If so, return this indecomposable `L` and an isomorphism from 
        ``L.direct_sum_repeat(s)`` to ``self``.

        TESTS ::

            sage: #long time (25 seconds)
            sage: from vector_bundle import atiyah_bundle
            sage: F.<x> = FunctionField(GF(7))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: V = atiyah_bundle(K, 2, 0)
            sage: W = V.direct_sum_repeat(2)
            sage: T = matrix(K, 4, 4,
            ....:            [x+1, 4, 3*x+4, 6*x+6,
            ....:             4*x+5, 6*x+5, 2*x+1, 4*x+3,
            ....:             3*x+1, 5*x, 3*x+1, x+6,
            ....:             5*x+4, 6*x, 5*x+2, 6*x+6])           
            sage: W = W.apply_isomorphism(T)
            sage: ind, s, isom = W._indecomposable_power_split()
            sage: s
            2
            sage: V._isomorphism_indecomposable(ind) is not None
            True
            sage: ind.direct_sum_repeat(s).hom(W).is_isomorphism(isom)
            True
        """
        End = self.end()
        A, to_A, from_A = End.global_algebra()
        (S, to_S, from_S), factors = End._global_algebra_split()
        if len(factors) > 1:
            return None, None
        split = factors[0]
        K = split._K
        s = split._n
        idems = [diagonal_matrix(K, [0]*i + [1] + [0]*(s-i-1))
                 for i in range(s)]
        idems = [from_A(from_S(split.from_M(idem))) for idem in idems]
        images = [End.image(idem) for idem in idems]
        factor = images[0][0]
        isoms = [factor._isomorphism_indecomposable(im[0]) for im in images[1:]]
        phis = ([images[0][1]]
                + [im[1]*isom for im, isom in zip(images[1:], isoms)])
        return (factor,
                len(phis),
                block_matrix(self._function_field, [phis]))

    def split(self):
        r"""
        Return a list of indecomposable bundles ``inds``, a list of integers 
        `ns` and an isomorphism from 
        `\bigoplus_{\mathrm{ind} \in \mathrm{inds}} 
        \mathrm{ind}^{n_\mathrm{ind}}` to ``self``.

        EXAMPLES::

            sage: # long time (20 seconds)
            sage: from vector_bundle import atiyah_bundle, trivial_bundle
            sage: F.<x> = FunctionField(GF(7))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: triv = trivial_bundle(K)
            sage: V = atiyah_bundle(K, 2, 0)
            sage: W = triv.direct_sum_repeat(2).direct_sum(V)
            sage: T = matrix(K, 4, 4,
            ....:            [x+1, 4, 3*x+4, 6*x+6,
            ....:             4*x+5, 6*x+5, 2*x+1, 4*x+3,
            ....:             3*x+1, 5*x, 3*x+1, x+6,
            ....:             5*x+4, 6*x, 5*x+2, 6*x+6])           
            sage: W = W.apply_isomorphism(T)
            sage: inds, ns, isom = W.split()
            sage: b1 = [ind.rank() for ind in inds] == [1, 2]
            sage: b2 = [ind.rank() for ind in inds] == [2, 1]
            sage: b1 or b2
            True
            sage: b1 = ns == [1, 2]
            sage: b2 = ns == [2, 1]
            sage: b1 or b2
            True
            sage: sum = inds[0].direct_sum_repeat(ns[0])
            sage: sum = sum.direct_sum(inds[1].direct_sum_repeat(ns[1]))
            sage: sum.hom(W).is_isomorphism(isom)
            True
        """
        K = self._function_field
        End = self.end()
        A, to_A, from_A = End.global_algebra()
        (S, to_S, from_S), splits = End._global_algebra_split()
        injections = [[from_A(from_S(s.from_M(diagonal_matrix(
            s._K,
            [0]*i + [1] + [0]*(s._n-1-i))))) 
                           for i in range(s._n)]
                          for s in splits]
        images = [[End.image(inj) for inj in injs] for injs in injections]
        inds = [im[0][0] for im in images]
        phis = [[ims[0][1]] 
                + [im[1] * ind._isomorphism_indecomposable(im[0]) 
                   for im in ims[1:]]
                for ind,ims in zip(inds, images)]
        ns = [len(injs) for injs in injections]
        isom = block_matrix([sum(phis, [])])
        return inds, ns, isom

    def _isomorphism_to_small_field(self, other):
        r"""
        Return an isomorphism from self to other if it exists and None otherwise
        """
        inds_self, ns_self, isom_self = self.split()
        inds_other, ns_other, isom_other = other.split()
        if sorted(ns_self) != sorted(ns_other):
            return None
        isoms = [[ind_self._isomorphism_indecomposable(ind_other) 
                  for ind_other in inds_other] for ind_self in inds_self]
        fits = [[i for i, iso in enumerate(isos) if iso is not None] 
                for isos in isoms]
        if any([len(fit) != 1 for fit in fits]):
            return None
        #We now know that self and other are isomorphic
        fits = [fit[0] for fit in fits]
        ranks_self = [ind.rank() for ind in inds_self]
        ranks_other = [ind.rank() for ind in inds_other]
        s = len(inds_self)
        blocks = [block_diagonal_matrix([isoms[i][fits[i]]]*ns_self[i]) 
                  for i in range(s)]
        isom = block_matrix([[blocks[i] if j == fits[i] else 0 
                              for j in range(s)] 
                             for i in range(s)])
        return isom_other * isom * isom_self**-1

    def isomorphism_to(self, other):
        r"""
        Return an isomorphism from self to other if it exists and None otherwise

        EXAMPLES ::

            sage: from vector_bundle import (trivial_bundle, canonical_bundle,
            ....:                            atiyah_bundle)
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: triv = trivial_bundle(K)
            sage: can = canonical_bundle(K)
            sage: iso = triv.isomorphism_to(can)
            sage: triv.hom(can).is_isomorphism(iso)
            True
            sage: V = can.direct_sum(atiyah_bundle(K, 2, 0, can))\
            ....:     .direct_sum(triv)
            sage: W = can.direct_sum(atiyah_bundle(K, 2, 0)).direct_sum(can)
            sage: iso = V.isomorphism_to(W)
            sage: V.hom(W).is_isomorphism(iso)
            True
            
        WARNING:

        Not well implemented for infinite fields: need to specify how to chose
        random elements and adequatly set the sample size.
        """
        s = len(self.end().h0())
        k = self._function_field.constant_base_field()
        if k.cardinality() > s:
            return self._isomorphism_to_large_field(
                    other,
                    integer_ceil(60/log(k.cardinality()/s)))
        return self._isomorphism_to_small_field(other)

    def apply_isomorphism(self, isom):
        r"""
        Isom is an invertible square matrix of order ``self.rank()``.
        Return the image of ``self`` by ``isom``.

        EXAMPLES ::

            sage: from vector_bundle import (trivial_bundle, canonical_bundle,
            ....:                            atiyah_bundle)
            sage: F.<x> = FunctionField(GF(3))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: triv = trivial_bundle(K)
            sage: can = canonical_bundle(K)
            sage: iso = triv.isomorphism_to(can)
            sage: triv.hom(can).is_isomorphism(iso)
            True
            sage: V = can.direct_sum(atiyah_bundle(K, 2, 0, can))\
            ....:     .direct_sum(triv)
            sage: W = can.direct_sum(atiyah_bundle(K, 2, 0)).direct_sum(can)
            sage: iso = V.isomorphism_to(W)
            sage: V.apply_isomorphism(iso) == W
            True
        """
        return VectorBundle(self._function_field,
                            self._ideals,
                            isom * self._g_finite,
                            isom * self._g_infinite,
                            check=False)
