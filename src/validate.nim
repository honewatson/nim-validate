# nim_validate
# Copyright honewatson
# String validation for nim.  Validate your tainted strings.
import regex
import tables

const EMAIL_REGEX = re"^[_]*([a-z0-9]+(\.|_*)?)+@([a-z][a-z0-9-]+(\.|-*\.))+[a-z]{2,6}$"
const DOMAIN_REGEX = re"^([a-z][a-z0-9-]+(\.|-*\.))+[a-z]{2,6}$"
const URL_REGEX = re"^(http(s)?(:\/\/))?(www\.)?[a-zA-Z0-9-_\.]+(\.[a-zA-Z0-9]{2,})([-a-zA-Z0-9:%_\+.~#?&\/\/=]*)"
# const IPV6 = re"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$"
const MAC_ADDRESS_REGEX = re"^([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])$"
const HEX_COLOR_REGEX = re"^#?([0-9A-F]{3}|[0-9A-F]{6})$"
const HEX_REGEX = re"^(0x)?[0-9A-F]+$"
const ALPHA_REGEX = re"^[A-Za-z]+$"
  # numeric characters validation
const NUMERIC_REGEX = re"^([0-9]+)$"
# alpha numeric characters validation
const ALPHA_NUMERIC_REGEX = re"^[0-9A-Za-z]+$"
# md5 validation
const MD5_REGEX = re"^[a-f0-9]{32}$"
# base64 validation
const BASE64_REGEX = re"^[a-zA-Z0-9+\/]+={0,2}$"
#&& (self.size % 4 === 0)
# slug validation
const SLUG_REGEX = re"^([a-zA-Z0-9_-]+)$"
# credit card validation
# const CREDIT_CARD = re"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|(222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})|62[0-9]{14}$"

type
    Email* = distinct string
    Domain* = distinct string
    Url* = distinct string
    MacAddress* = distinct string
    HexColor* = distinct string 
    Hex* = distinct string
    Alpha* = distinct string
    Numeric* = distinct string
    AlphaNumeric* = distinct string
    Md5* = distinct string
    Base64* = distinct string
    Slug* = distinct string

proc validate*(str: Email): bool =
    string(str).match(EMAIL_REGEX).isSome

proc validate*(str: Domain): bool = 
    string(str).match(DOMAIN_REGEX).isSome

proc validate*(str: Url): bool = 
    string(str).match(URL_REGEX).isSome

proc validate*(str: MacAddress): bool =
    string(str).match(MAC_ADDRESS_REGEX).isSome

proc validate*(str: HexColor): bool =
    string(str).match(HEX_COLOR_REGEX).isSome

proc validate*(str: Hex): bool =
    string(str).match(HEX_REGEX).isSome

proc validate*(str: Alpha): bool =
    string(str).match(ALPHA_REGEX).isSome

proc validate*(str: Numeric): bool =
    string(str).match(NUMERIC_REGEX).isSome

proc validate*(str: AlphaNumeric): bool =
    string(str).match(ALPHA_NUMERIC_REGEX).isSome

proc validate*(str: Md5): bool =
    string(str).match(MD5_REGEX).isSome

proc validate*(str: Base64): bool =
    string(str).match(BASE64_REGEX).isSome

proc validate*(str: Slug): bool =
    string(str).match(SLUG_REGEX).isSome
