N = 62387894035418985698242022646275807605194679344365009899365459815203376737681900577520466843998085872989197047617225377426154759277068445258234995920472065982815739527789692366910793544928511496519209241804812574517246910291242675632138077378790733940907981899512378033452346295596690124443127890557871685659
e = 17
d0 = 11059868489760577511644758633114276410580560089242109049148091134637121906698625213322809290608670483496315488167696768173166807126651570689024279683206705
c = 57735375271596117629128294064952886774532841196587926364205710277153873207448204512064080133729740341663083309508175719339823648485948175559641144964669514579560992689754979307882768224501547106728674174465274821708431189736162771370377886236606791560102549069685611544154389066471
d0bits = 512
nBits = 1024

X = var('X')
found = False
for k in range(1,e+1):
	if found:
		break
	print("Attempt",k)
	results = solve_mod([e*d0 - k*(N-X+1) == 1], 2^d0bits)
	for x in results:
		s = ZZ(x[0])
		P = var('P')
		p0_results = solve_mod([P^2 - s*P + N == 0], 2^d0bits)
		for y in p0_results:
			p0 = int(y[0])
			PR.<z> = PolynomialRing(Zmod(N))
			f = 2^d0bits*z + p0
			f = f.monic()
			roots = f.small_roots(X=2^(nBits//2 - d0bits + 1), beta=0.1)
			if roots:
				x0 = roots[0]
				p = gcd(2^d0bits*x0 + p0, N)
				q = N//ZZ(p)
				d = pow(e,-1,(p-1)*(q-1))
				print(int(pow(c,d,N)).to_bytes(10,"big"))
				found = True