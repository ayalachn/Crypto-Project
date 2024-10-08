# -*- coding: utf-8 -*-
import random

import warnings

# Python3 compatibility
try:
    LONG_TYPE = long
except NameError:
    LONG_TYPE = int


"""
Returns {s, t} in the Extended Euclidean Algorithm:
    a*s + b*t = 1
"""
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

"""
Returns the inverse of a under modulo p
a^-1 (mod p) = x (mod p)
"""
def mod_inv(a, p):
    if a < 0:
        return p - mod_inv(-a, p)
    g, x, y = egcd(a, p)
    if g != 1:
        raise ArithmeticError("Modular inverse does not exist")
    else:
        return x % p

"""
y^2 ≡ x^3 + a*x + b
"""
class Curve(object):
    def __init__(self, a, b, field, name="undefined"):
        self.name = name
        self.a = a
        self.b = b
        self.field = field
        self.g = Point(self, self.field.g[0], self.field.g[1])

    """
    Let a ∈ ℝ, b ∈ ℝ, be constants such that 
       4a³ + 27b² ≠ 0
    Curve must be non-singular.   
    """
    def is_singular(self):
        return (4 * self.a**3 + 27 * self.b**2) % self.field.p == 0
    """
    Returns True if point (x,y) is on curve. False if not.
    """
    def on_curve(self, x, y):
        return (y**2 - x**3 - self.a * x - self.b) % self.field.p == 0
    """
    equals function - returns True if given curve is equal to this curve. 
    returns False otherwise.
    Called each time we do curve1 == curve2
    """
    def __eq__(self, other):
        if not isinstance(other, Curve):
            return False
        return self.a == other.a and self.b == other.b and self.field == other.field
    """
    not equals function - returns true if given curve is not equal to this curve.
    Called each time we do curve1 != curve2
    """
    def __ne__(self, other):
        return not self.__eq__(other)
    """
    toString of curve
    """
    def __str__(self):
        return "\"%s\" => y^2 = x^3 + %dx + %d (mod %d)" % (self.name, self.a, self.b, self.field.p)


class SubGroup(object):
    def __init__(self, p, g, n, h):
        self.p = p
        self.g = g
        self.n = n
        self.h = h

    def __eq__(self, other):
        if not isinstance(other, SubGroup):
            return False
        return self.p == other.p and self.g == other.g and self.n == other.n and self.h == other.h

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "Subgroup => generator %s, order: %d, cofactor: %d on Field => prime %d" % (self.g, self.n,
                                                                                           self.h, self.p)

    def __repr__(self):
        return self.__str__()

"""
G has an identity element e.  
There is an e in G such that x + e = e + x = x for all x ∈ G.

e = Infinity
"""
class Inf(object):
    def __init__(self, curve, x=None, y=None):
        self.x = x
        self.y = y
        self.curve = curve

    def __eq__(self, other):
        if not isinstance(other, Inf):
            return False
        return self.curve == other.curve

    def __ne__(self, other):
        return not self.__eq__(other)

    def __add__(self, other):
        if isinstance(other, Inf):
            return Inf()
        if isinstance(other, Point):
            return other
        raise TypeError("Unsupported operand type(s) for +: '%s' and '%s'" % (other.__class__.__name__,
                                                                                  self.__class__.__name__))

    def __sub__(self, other):
        if isinstance(other, Inf):
            return Inf()
        if isinstance(other, Point):
            return other
        raise TypeError("Unsupported operand type(s) for +: '%s' and '%s'" % (other.__class__.__name__,
                                                                                  self.__class__.__name__))

    def __str__(self):
        return "%s on %s" % (self.__class__.__name__, self.curve)

    def __repr__(self):
        return self.__str__()

"""
Point on curve
"""
class Point(object):
    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y
        self.p = self.curve.field.p
        self.on_curve = True
        if not self.curve.on_curve(self.x, self.y): # Check if point is on curve
            warnings.warn("Point (%d, %d) is not on curve \"%s\"" % (self.x, self.y, self.curve))
            self.on_curve = False

    def __m(self, p, q):
        if p.x == q.x:
            return (3 * p.x**2 + self.curve.a) * mod_inv(2 * p.y, self.p)
        else:
            return (p.y - q.y) * mod_inv(p.x - q.x, self.p)
    """
    equals function - returns True if given point is equal to this point. 
    returns False otherwise.
    Called each time we do point1 == point2
    """
    def __eq__(self, other):
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y and self.curve == other.curve
    """
    not equals function - returns true if given point is not equal to this point.
    Called each time we do point1 != point2
    """
    def __ne__(self, other):
        return not self.__eq__(other)
    """
    Add given point to this point. Called each time we do point1 + point2
    """
    def __add__(self, other):
        if isinstance(other, Inf): # P+O = P
            return self
        if isinstance(other, Point): # P + Q 
            if self.x == other.x and self.y != other.y: # Case 2: x1=x2; y1 = -y2
                return Inf(self.curve)
            elif self.curve == other.curve: # Case 1 & 3: case x1!=x2 and case x1=x2; y1=y2
                m = self.__m(self, other)
                x_r = (m**2 - self.x - other.x) % self.p
                y_r = -(self.y + m * (x_r - self.x)) % self.p
                return Point(self.curve, x_r, y_r)
            else:
                raise ValueError("Cannot add points belonging to different curves")
        else:
            raise TypeError("Unsupported operand type(s) for +: '%s' and '%s'" % (other.__class__.__name__,
                                                                                  self.__class__.__name__))
    """
    Sub given point from this point. Called each time we do point1 - point2
    """
    def __sub__(self, other):
        if isinstance(other, Inf): # P - O = P + O = P
            return self.__add__(other)
        if isinstance(other, Point): # P - Q = (x1, y1) - (x2, y2) = (x1, y1) + (x2, -y2)
            return self.__add__(Point(self.curve, other.x, -other.y % self.p))
        else:
            raise TypeError("Unsupported operand type(s) for -: '%s' and '%s'" % (other.__class__.__name__,
                                                                                  self.__class__.__name__))
    """
    Multiply point by integer. Called each time we do n*point
    """
    def __mul__(self, other):
        if isinstance(other, Inf): # Infinity*Point = Point+Point+.... = Infinity
            return Inf(self.curve)
        if isinstance(other, int) or isinstance(other, LONG_TYPE):
            if other % self.curve.field.n == 0: # x + e = e + x => x - x = x+e - (x+e) = e - e = e + (-e) = e
                return Inf(self.curve)
            if other < 0: # -n*(x,y) = -(x,y) - (x,y) - ... - (x,y) = (x,-y)+(x,-y)+..+(x,-y)
                addend = Point(self.curve, self.x, -self.y % self.p) # P = (x,-y)
            else:
                addend = self # P = (x,y)
            result = Inf(self.curve) # res = 0
            # Iterate over all bits starting by the LSB
            for bit in reversed([int(i) for i in bin(abs(other))[2:]]):
                if bit == 1:
                    result += addend # res = P + P + ... + P
                addend += addend #  Q = P+P
            return result
        else:
            raise TypeError("Unsupported operand type(s) for *: '%s' and '%s'" % (other.__class__.__name__,
                                                                                  self.__class__.__name__))

    def __rmul__(self, other):
        return self.__mul__(other)
    """
    toString of point
    """
    def __str__(self):
        return "(%d, %d) %s %s" % (self.x, self.y, "on" if self.on_curve else "off", self.curve)

    def __repr__(self):
        return self.__str__()


def make_keypair(curve):
    priv = random.randint(1, curve.field.n)
    pub = priv * curve.g
    return Keypair(curve, priv, pub)


class Keypair(object):
    def __init__(self, curve, priv=None, pub=None):
        if priv is None and pub is None:
            raise ValueError("Private and/or public key must be provided")
        self.curve = curve
        self.can_sign = True
        self.can_encrypt = True
        if priv is None:
            self.can_sign = False
        self.priv = priv
        self.pub = pub
        if pub is None:
            self.pub = self.priv * self.curve.g


class ECDH(object):
    def __init__(self, keypair):
        self.keypair = keypair

    def get_secret(self, keypair):
        # Don;t check if both keypairs are on the same curve. Should raise a warning only
        if self.keypair.can_sign and keypair.can_encrypt:
            secret = self.keypair.priv * keypair.pub
        elif self.keypair.can_encrypt and keypair.can_sign:
            secret = self.keypair.pub * keypair.priv
        else:
            raise ValueError("Missing crypto material to generate DH secret")
        return secret
