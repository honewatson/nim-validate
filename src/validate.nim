# nim_validate
# Copyright honewatson
# String validation for nim.  Validate your tainted strings.
import regex
import tables

proc validate*(regex: Regex): (proc(str: string): bool) =
    return proc(str: string): bool =
        str.match(regex).isSome

const EMAIL = re"^[_]*([a-z0-9]+(\.|_*)?)+@([a-z][a-z0-9-]+(\.|-*\.))+[a-z]{2,6}$"
const DOMAIN = re"^([a-z][a-z0-9-]+(\.|-*\.))+[a-z]{2,6}$"
const URL = re"^(http(s)?(:\/\/))?(www\.)?[a-zA-Z0-9-_\.]+(\.[a-zA-Z0-9]{2,})([-a-zA-Z0-9:%_\+.~#?&\/\/=]*)"
const IPV6 = re"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$"
const MAC_ADDRESS = re"^([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])$"
const HEX_COLOR = re"^#?([0-9A-F]{3}|[0-9A-F]{6})$"
const HEX = re"^(0x)?[0-9A-F]+$"
const ALPHA = re"^[A-Za-z]+$"
  # numeric characters validation
const NUMERIC = re"^([0-9]+)$"
# alpha numeric characters validation
const ALPHA_NUMERIC = re"^[0-9A-Za-z]+$"
# md5 validation
const MD5 = re"^[a-f0-9]{32}$"
# base64 validation
const BASE64 = re"^[a-zA-Z0-9+\/]+={0,2}$"
#&& (self.size % 4 === 0)
# slug validation
const SLUG = re"^([a-zA-Z0-9_-]+)$"
# credit card validation
const CREDIT_CARD = re"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|(222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})|62[0-9]{14}$"

type
    TableValidator* = Table[string, proc(str: string): bool]


proc newTableValidator*(): TableValidator =
    result = initTable[string, proc(data: string): bool]()
    result["email"] = validate(EMAIL)
    result["domain"] = validate(DOMAIN)
    result["url"] = validate(URL)
    result["ipv6"] = validate(IPV6)
    result["mac_address"] = validate(MAC_ADDRESS)
    result["hex_color"] = validate(HEX_COLOR)
    result["hex"] = validate(HEX)
    result["alpha"] = validate(ALPHA)
    result["numeric"] = validate(NUMERIC)
    result["alpha_numeric"] = validate(ALPHA_NUMERIC) 
    result["md5"] = validate(MD5)
    result["base64"] = validate(BASE64)
    result["slug"] = validate(SLUG)
    result["credit_card"] = validate(CREDIT_CARD)

let validateEmail* = validate(EMAIL)
let validateDomain* = validate(DOMAIN)
let validateUrl* = validate(URL)
let validateIpv6* = validate(IPV6)
let validateMacAddress* = validate(MAC_ADDRESS)
let validateHexColor* = validate(HEX_COLOR)
let validateHex* = validate(HEX)
let validateAlpha* = validate(ALPHA)
let validateNumeric* = validate(NUMERIC)
let validateAlphaNumeric* = validate(ALPHA_NUMERIC)
let validateMd5* = validate(MD5)
let validateBase64* = validate(BASE_64)
let validateSlug* = validate(SLUG)
let validateCreditCard = validate(CREDIT_CARD)

