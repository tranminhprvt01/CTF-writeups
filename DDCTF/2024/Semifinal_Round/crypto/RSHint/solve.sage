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




from Crypto.Util.number import *





hint=10398007451952402830098981140304200278885641812684581200202893860339400378281061894143709816017659342552066877779393782160576484467891738946995167046926336
n=121214947327748020502777023190878976140343196504351424747746917651971310176734565861711686576303852719512975692942423960140537593078806624661577963975699878704754998231961016707994451940952546650306328858586814463132486310932040520556584587608277086989709379496698239067708899687070417541004925355774406670643
c=67531116129625482653869325082461739042756000060633866771324711329948181840085867139295923623784039879947544320965967625215133695889918824479791437090772066663963267995387305729346450624170530384460202956474513186256563246461212862174433114032015608474672654782710223692856746704472480046371024166960954540955
e = 65537



P.<x> = PolynomialRing(Zmod(n))


for s in range(100, 171):
    f = hint + x
    x = small_roots(f, [2**s], 3, 3)
    p = int(f(x[0]))
    break

q = n//p

phi = (p-1)*(q-1)

d = inverse(e, phi)

print(long_to_bytes(int(pow(c, int(d), n))))
	
	