import cmath
class Complex:
    def __init__(self, real, imag):
        self.real = real
        self.imag = imag

    def __add__(self, other):
        if isinstance(other, Complex):
            return Complex(self.real + other.real, self.imag + other.imag)
        elif isinstance(other, (int, float)):
            return Complex(self.real + other, self.imag)
        return NotImplemented

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if isinstance(other, Complex):
            return Complex(self.real - other.real, self.imag - other.imag)
        elif isinstance(other, (int, float)):
            return Complex(self.real - other, self.imag)
        return NotImplemented

    
    def __rsub__(self, other):
        if isinstance(other, (int, float)):
            return Complex(other - self.real, -self.imag)
        return NotImplemented

    def __mul__(self, other):
        if isinstance(other, Complex):
            real_part = self.real * other.real - self.imag * other.imag
            imag_part = self.real * other.imag + self.imag * other.real
            return Complex(real_part, imag_part)
        elif isinstance(other, (int, float)):
            return Complex(self.real * other, self.imag * other)
        return NotImplemented

    def __rmul__(self, other):
        return self.__mul__(other)

    def __truediv__(self, other):
        if isinstance(other, Complex):
            denom = other.real**2 + other.imag**2
            if denom == 0:
                raise ZeroDivisionError("division by zero")
            real_part = (self.real * other.real + self.imag * other.imag) / denom
            imag_part = (self.imag * other.real - self.real * other.imag) / denom
            return Complex(real_part, imag_part)
        elif isinstance(other, (int, float)):
            if other == 0:
                raise ZeroDivisionError("division by zero")
            return Complex(self.real / other, self.imag / other)
        return NotImplemented

    def __rtruediv__(self, other):
        if isinstance(other, (int, float)):
            if self.real == 0 and self.imag == 0:
                raise ZeroDivisionError("division by zero")
            denom = self.real**2 + self.imag**2
            real_part = (other * self.real) / denom
            imag_part = (-other * self.imag) / denom
            return Complex(real_part, imag_part)
        return NotImplemented

    def __pow__(self, exponent):
        if isinstance(exponent, int):
            exponent = exponent%4
            if exponent == 2:
                return -1  
            elif exponent == 1:
                return self  
            elif exponent == 0:
                return 1  
            elif exponent == 3:
                return Complex(0, -1) 
        return NotImplemented
    def __rpow__(self, base):
        if isinstance(base, (int, float)):
            polar = cmath.polar(complex(self.real, self.imag))
            result = cmath.rect(base ** polar[0], polar[1] * base)
            return Complex(result.real, result.imag)
        return NotImplemented

    def __eq__(self, other):
        if isinstance(other, Complex):
            return self.real == other.real and self.imag == other.imag
        elif isinstance(other, (int, float)):
            return self.real == other and self.imag == 0
        return NotImplemented

    def __repr__(self):
        return f"{self.real} + {self.imag}i"

    def __str__(self):
        
        return f"{self.real} + {self.imag}i"

    def __neg__(self):
        return Complex(-self.real, -self.imag)

    def __abs__(self):
        return (self.real**2 + self.imag**2) ** 0.5

# Example usage
