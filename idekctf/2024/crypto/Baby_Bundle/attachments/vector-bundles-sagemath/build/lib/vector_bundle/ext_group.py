r"""
This module implements the ExtGroup and ExtGroupElement classes used for
building extensions of vector bundles.

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

from sage.structure.sage_object import SageObject
from sage.structure.element import Matrix
from sage.matrix.special import block_matrix
from sage.modules.free_module_element import vector

class ExtGroup(SageObject):
    r"""
    The group of extensions of ``left`` by ``right``.

    The group `Ext^1(\mathrm{left},\mathrm{right})` is
    `H^1(\mathrm{left}^\vee \otimes \mathrm{right})`.
    Its elements may be represented as matrices of infinite répartitions
    lying in `M_{\mathrm{right}.rank(),\mathrm{left}.rank()}(R)` or as
    vectors of length ``self.dim()`` with coefficients in the coefficient
    field, representing linear forms on
    `H^0(\omega \otimes \mathrm{right}^\vee \otimes \mathrm{left})`, where
    `\omega` is the canonical bundle of the function field of ``left`` and
    ``right``
    The two representations are related via Serre duality.

    If ``precompute_basis`` is set to ``True``, a basis of répartition
    matrices is computed. Its element represent the linear forms
    ``vector([0,...,0,1,0,...,0])``. Otherwise, linear forms are converted
    to elements of the `H^1` on the fly. You should set ``precompute_basis``
    to ``True`` only if you plan to create several extensions with this group.

    INPUT:

        - ``left`` -- VectorBundle
        - ``right`` -- VectorBundle; must have the same function field as left
        - ``precompute_basis`` -- boolean

    EXAMPLES ::

        sage: from vector_bundle import VectorBundle, trivial_bundle
        sage: F.<x> = FunctionField(GF(3))
        sage: triv = trivial_bundle(F)
        sage: triv.extension_group(triv)
        Extension group of Vector bundle of rank 1 over Rational function field in x over Finite Field of size 3 by Vector bundle of rank 1 over Rational function field in x over Finite Field of size 3.
    """
    def __init__(self, left, right, precompute_basis=False):
        if not left._function_field == right._function_field:
            raise ValueError('left and right should have the same function'
                             + 'field')
        self._left = left
        self._right = right
        self._hom = left.hom(right)
        self._ext_dual_basis, self._ext_dual_bundle = self._hom.h1_dual()
        self._s = len(self._ext_dual_basis)
        if precompute_basis:
            self._compute_basis()
        else:
            self._basis = None

    def __hash__(self):
        return hash((self._left, self._right))

    def __eq__(self, other):
        return self._left == other._left and self._right == other._right

    def _repr_(self):
        return "Extension group of %s by %s." % (self._left, self._right)

    def _compute_basis(self):
        r"""
        Compute the representation of basis elements of ``self`` as elements of the `H^1`
        """
        if self._basis is None:
            self._basis = [self._hom.h1_element(
                vector([0] * i + [1] + [0] * (self._s-i-1)))
                           for i in range(self._s)]

    def dim(self):
        r"""
        Return the dimension of the extension group as a vector space over the
        base coefficient field

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(11))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^5 - 1)
            sage: ksi = VectorBundle(K, K.places_finite()[0].divisor())
            sage: ext = ksi.extension_group(ksi.dual()); ext.dim()
            3
        """
        return self._s

    def left(self):
        r"""
        Return the left vector bundle of ``self``.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: L1 = VectorBundle(F, x.zeros()[0].divisor())
            sage: L2 = VectorBundle(F, x.poles()[0].divisor())
            sage: ext = L1.extension_group(L2); ext.left() == L1
            True
        """
        return self._left

    def right(self):
        r"""
        Return the right vector bundle of ``self``.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(3))
            sage: L1 = VectorBundle(F, x.zeros()[0].divisor())
            sage: L2 = VectorBundle(F, x.poles()[0].divisor())
            sage: ext = L1.extension_group(L2); ext.right() == L2
            True
        """
        return self._right

    def dual_bundle(self):
        r"""
        Return the dual bundle of the `\mathcal{Ext}^1` bundle. This bundle
        is `\omega \otimes \mathrm{right}^\vee \otimes \mathrm{left}`, where
        `\omega` is a canonical line bundle of `K`.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(11))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^5 - 1)
            sage: ksi = VectorBundle(K, K.places_finite()[0].divisor())
            sage: ext = ksi.extension_group(ksi.dual()); ext.dual_bundle()
            Homomorphism bundle from Vector bundle of rank 1 over Function 
            field in y defined by y^2 + 10*x^5 + 10 to Vector bundle of rank 1
            over Function field in y defined by y^2 + 10*x^5 + 10
        """
        return self._ext_dual_bundle

    def dual_basis(self):
        r"""
        This is the same as ``self.dual_bundle().h0()``
        The output basis is dual to ``self.basis()`` under Serre duality.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(11))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^5 - 1)
            sage: ksi = VectorBundle(K, K.places_finite()[0].divisor())
            sage: ext = ksi.extension_group(ksi.dual()); ext.dual_basis()
            [[x^4/(x^5 + 6)], [x^5/(x^5 + 6)], [(x^2/(x^5 + 6))*y + 10*x^2/(x^5 + 6)]]
        """
        return self._ext_dual_basis

    def basis(self):
        r"""Return a basis of `Ext^1` group. Its element are matrices of
        infinite répartitions represented by field elements.

        Computes and stores the basis if it was not precomputed yet.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle
            sage: F.<x> = FunctionField(GF(11))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^5 - 1)
            sage: ksi = VectorBundle(K, K.places_finite()[0].divisor())
            sage: ext = ksi.extension_group(ksi.dual()); ext.basis()
            [[(x^9/(x^10 + 2*x^5 + 1))*y], [(x^3/(x^5 + 1))*y], [x^6/(x^5 + 1)]]
        """
        self._compute_basis()
        return self._basis

    def _extension_from_ext_element(self, ext):
        r"""
        Return the extension of ``self.left() by ``self.right()`` encoded by
        ``ext``.

        ``ext`` is a matrix of elements of ``self._function_field`` which
        represents the constant value over the infinite places of a répartition
        matrix with support at infinity representing an element of
        `H^1(\mathrm{hom}(\mathrm{left},\mathrm{right}))`.
        Such an element encodes an extension `V`:
        `0 \to \mathrm{other} \to V \to \mathrm{self} \to 0`

        INPUT:

        - ``ext`` -- a matrix of dimension ``right.rank(),left.rank()``
        """
        from vector_bundle import VectorBundle
        function_field = self._left._function_field
        ideals = self._right._ideals + self._left._ideals
        g_finite = block_matrix([[self._right._g_finite, 0],
                                 [0, self._left._g_finite]])
        g_infinite = block_matrix([[self._right._g_infinite,
                                    -ext * self._left._g_infinite],
                                   [0, self._left._g_infinite]])
        return VectorBundle(function_field, ideals, g_finite, g_infinite)

    def _extension_from_linear_form(self, form):
        if self._basis is None:
            ext = self._hom.h1_element(form)
            ext = self._ext_dual_bundle._vector_to_matrix(ext).transpose()
        else:
            ext = sum([coeff * e for coeff, e in zip(form, self._basis)])
        return self._extension_from_ext_element(ext)

    def extension(self, ext=None):
        r"""
        Return the extension of ``self.left()`` by ``self.right()`` encoded by
        ``ext``.

        ``ext`` can be a matrix of elements of ``self._function_field``
        which represents the constant value over the infinite places of a
        répartition matrix with support at infinity representing an element of
        `H^1(\mathrm{hom}(\mathrm{left},\mathrm{right}))`.
        Such an element encodes an extension `V`:
        `0 \to \mathrm{other} \to V \to \mathrm{self} \to 0`

        ``ext`` can also be a vector of length `self.dim()` representing an
        extension in the basis of the Ext vector space.

        By default, ``ext`` is chosen as any non trivial extension.

        EXAMPLES ::

            sage: from vector_bundle import VectorBundle, trivial_bundle
            sage: F.<x> = FunctionField(GF(11))
            sage: R.<y> = F[]
            sage: K.<y> = F.extension(y^2 - x^3 - x)
            sage: triv = trivial_bundle(K)
            sage: ext = triv.extension_group(triv)
            sage: V = ext.extension()
            sage: V.rank()
            2
            sage: V.determinant() == triv
            True
            sage: V.h0()
            [(1, 0)]
            sage: V.end().h0()
            [
            [0 1]  [1 0]
            [0 0], [0 1]
            ]
        """
        if ext is None:
            ext = vector([1] + [0]*(self._s-1))
        if isinstance(ext,Matrix):
            return self._extension_from_ext_element(ext)
        else:
            return self._extension_from_linear_form(ext)
