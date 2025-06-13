import itertools

def small_roots(f, bounds, m=1, d=None):
	if not d:
		d = f.degree()

	if isinstance(f, Polynomial):
		x, = polygens(f.base_ring(), f.variable_name(), 1)
		f = f(x)

	R = f.base_ring()
	N = R.cardinality()
	
	f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)

	G = Sequence([], f.parent())
	for i in range(m+1):
		base = N^(m-i) * f^i
		for shifts in itertools.product(range(d), repeat=f.nvariables()):
			g = base * prod(map(power, f.variables(), shifts))
			G.append(g)

	B, monomials = G.coefficient_matrix()
	monomials = vector(monomials)

	factors = [monomial(*bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)

	B = B.dense_matrix().LLL()

	B = B.change_ring(QQ)
	for i, factor in enumerate(factors):
		B.rescale_col(i, 1/factor)

	H = Sequence([], f.parent().change_ring(QQ))
	for h in filter(None, B*monomials):
		H.append(h)
		I = H.ideal()
		if I.dimension() == -1:
			H.pop()
		elif I.dimension() == 0:
			roots = []
			for root in I.variety(ring=ZZ):
				root = tuple(R(root[var]) for var in f.variables())
				roots.append(root)
			return roots

	return []


c = 45213784224458556989302273697721458755947352802729170735021659544389617065743699487407481946193893681973447268710838523708023111230234362955902000768282322845596195625562257172194101234317031044130370737585840986417388612454936969850362545760939217024933618132817830690159026260197920184029673875954950534606

n = 119013667572167009136191086616452146837590194600725458508857024260026174572184862727097334515725958630744619201036719834301104491895795470231427534373902478933045450801372035480701591551197573004846537698078057260460279196411048217290177559346249689629950908278761509084087907309232611314102477305479419906711

leak = 119013667572167009136191086616452146837590194600725458508857024260026174572184862727097334515725958630744619201036719834301104491895795470231427534368474996956302792785364036251700725513111826566076427923651354636497529544228768655331954316379458744264158671575241100482663130084854369965292738774417071426347

P.<x, y, z> = PolynomialRing(Zmod(n))


f = (x-1)^2 - (x-1)*(y-1+z-1) + n+1-(y+z)


print(small_roots(f, [2^20, 2^512, 2^512], 5, 5))