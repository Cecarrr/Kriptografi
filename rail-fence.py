def fence(lst, numrails):
    fence = [[None] * len(lst) for n in range(numrails)]
    rails = list(range(numrails - 1)) + list(range(numrails - 1, 0, -1))
    for n, x in enumerate(lst):
        fence[rails[n % len(rails)]][n] = x
    return [c for rail in fence for c in rail if c is not None]


def encode(text, n):
    return "".join(fence(text, n))


def decode(text, n):
    rng = range(len(text))
    pos = fence(rng, n)
    return "".join(text[pos.index(n)] for n in rng)


z = encode("ATTACK.AT.DAWN", 3)
print(z)
y = decode(z, 3)
print(y)
