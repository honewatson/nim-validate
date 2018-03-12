import unittest
import tables
import ../src/validate

suite "#newValidator()":
    var validator: TableValidator = newTableValidator()
    test "Create validator":
        check(validator.hasKey("email"))
    test "Validates email address":
        check(validator["email"]("hello@world.com"))