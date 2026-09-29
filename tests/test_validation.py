from app.validation import CN_RE, normalize_employee_key, normalize_mac


def test_normalize_mac_accepts_colon_form():
    assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_accepts_dash_form():
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_accepts_cisco_dotted_form():
    assert normalize_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_accepts_bare_hex():
    assert normalize_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_rejects_garbage():
    assert normalize_mac("not-a-mac") is None
    assert normalize_mac("aa:bb:cc:dd:ee") is None  # too short
    assert normalize_mac("gg:bb:cc:dd:ee:ff") is None  # non-hex


def test_cn_re_still_rejects_spaces():
    assert not CN_RE.match("bad cn!")
    assert CN_RE.match("valid-cn.01")


def test_normalize_employee_key_casefolds():
    assert normalize_employee_key("Juan Dela Cruz") == normalize_employee_key("juan dela cruz")


def test_normalize_employee_key_collapses_whitespace():
    assert normalize_employee_key("Juan  Dela   Cruz") == normalize_employee_key("Juan Dela Cruz")


def test_normalize_employee_key_trims():
    assert normalize_employee_key("  Juan Dela Cruz  ") == normalize_employee_key("Juan Dela Cruz")


def test_normalize_employee_key_distinguishes_different_names():
    assert normalize_employee_key("Juan Dela Cruz") != normalize_employee_key("J. Dela Cruz")


def test_normalize_employee_key_none_and_empty():
    assert normalize_employee_key(None) is None
    assert normalize_employee_key("") is None
    assert normalize_employee_key("   ") is None
