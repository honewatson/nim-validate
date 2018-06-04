import unittest
import tables
import ../src/validate


suite "validate()":
    test "Validates email address":
        check(validate("hello@world.com".Email))
        check(validate("hello@world".Email) == false)
    test "Validates Domain":
        check(validate("www.kangaroo.com.au".Domain))