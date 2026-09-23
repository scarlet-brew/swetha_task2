"""T02 -- the canonical form identity is derived from (design SS8.2).

    id = <prefix>_ + sha256(canonical_json(identity_fields))[:12]

This file covers the primitive: what `canonical_json` admits, what it refuses,
and the shape of the id that comes out. Which fields of which node kind are fed
to it is SS8.2's identity *table*, and that lives in `test_kernel_identity.py`.
The refusals matter as much as the accepted cases -- a float, a set or a naive
datetime each serialise in a way that is stable only by accident, and an id that
is stable only by accident is worse than no id at all.
"""

from __future__ import annotations

import datetime as dt
import re
import unittest

import _env  # noqa: F401  -- must precede the package import; puts src/ on sys.path

from siem_investigator import ids

ID_SHAPE = re.compile(r"^(rec|obs|edg|fnd|map|hyp)_[0-9a-f]{12}$")


class TestCanonicalJson(unittest.TestCase):
    def test_key_order_does_not_matter(self):
        """Three orders of one identity, one canonical form."""
        forms = [
            {"a": 1, "b": 2, "c": 3},
            {"c": 3, "a": 1, "b": 2},
            {"b": 2, "c": 3, "a": 1},
        ]
        rendered = {ids.canonical_json(form) for form in forms}
        self.assertEqual(len(rendered), 1, f"key order leaked into the canonical form: {rendered}")

    def test_three_key_orders_yield_one_id(self):
        """T02's first clause, stated on `node_id` rather than on the canonical
        form, because that is the function callers reach for."""
        forms = [
            {"record": "rec_a", "field": "f", "normalised_value": "v", "transform": "t"},
            {"transform": "t", "record": "rec_a", "field": "f", "normalised_value": "v"},
            {"field": "f", "normalised_value": "v", "transform": "t", "record": "rec_a"},
        ]
        produced = {ids.node_id("obs", form) for form in forms}
        self.assertEqual(len(produced), 1, f"key order leaked into the id: {produced}")

    def test_nested_key_order_does_not_matter(self):
        """Sorting has to reach all the way down -- `payload` is a nested dict."""
        left = {"outer": {"z": 1, "a": {"q": 2, "b": 3}}}
        right = {"outer": {"a": {"b": 3, "q": 2}, "z": 1}}
        self.assertEqual(ids.canonical_json(left), ids.canonical_json(right))

    def test_no_whitespace(self):
        self.assertEqual(ids.canonical_json({"a": [1, 2]}), '{"a":[1,2]}')

    def test_non_ascii_is_not_escaped(self):
        """`ensure_ascii=False`: a host or filename outside ASCII stays readable."""
        self.assertEqual(ids.canonical_json({"f": "café-Ü-é"}), '{"f":"café-Ü-é"}')
        self.assertNotIn("\\u", ids.canonical_json({"f": "café"}))

    def test_integral_float_narrows_to_int(self):
        """SS8.2: integers for byte counts. A count that took a detour through
        arithmetic must not hash differently from the same count read as an int."""
        self.assertEqual(ids.canonical_json({"bytes": 4096.0}), '{"bytes":4096}')
        self.assertEqual(ids.canonical_json({"bytes": 4096}), ids.canonical_json({"bytes": 4096.0}))

    def test_inexact_float_is_refused(self):
        with self.assertRaises(ids.IdentityError):
            ids.canonical_json({"ratio": 0.1})

    def test_nan_and_infinity_refused(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=bad):
                with self.assertRaises(ids.IdentityError):
                    ids.canonical_json({"x": bad})

    def test_set_is_refused_because_it_has_no_order(self):
        """A set's iteration order depends on hash randomisation, so admitting one
        would make identity depend on PYTHONHASHSEED."""
        with self.assertRaises(ids.IdentityError):
            ids.canonical_json({"x": {"a", "b"}})

    def test_non_string_key_refused(self):
        with self.assertRaises(ids.IdentityError):
            ids.canonical_json({1: "a"})

    def test_bool_stays_bool(self):
        """`True` must not narrow to `1`: they are different JSON documents."""
        self.assertEqual(ids.canonical_json({"x": True}), '{"x":true}')
        self.assertNotEqual(ids.canonical_json({"x": True}), ids.canonical_json({"x": 1}))

    def test_error_names_the_offending_path(self):
        with self.assertRaises(ids.IdentityError) as caught:
            ids.canonical_json({"outer": {"inner": [1, 0.5]}})
        self.assertIn("$.outer.inner[1]", str(caught.exception))


class TestCanonicalInstant(unittest.TestCase):
    def test_sub_second_precision_survives_verbatim(self):
        """A record whose raw timestamp already carries six fractional digits
        canonicalises back to the identical string."""
        parsed = dt.datetime(2026, 6, 12, 9, 7, 30, 394151, tzinfo=dt.timezone.utc)
        self.assertEqual(ids.canonical_instant(parsed), "2026-06-12T09:07:30.394151Z")

    def test_always_six_fractional_digits(self):
        """One instant, one spelling, whatever precision it arrived in. R7.1's
        perturbation alters sub-second precision deliberately, so a variable
        number of digits would make two spellings of one instant hash
        differently."""
        whole = dt.datetime(2026, 6, 12, 9, 7, 30, tzinfo=dt.timezone.utc)
        self.assertEqual(ids.canonical_instant(whole), "2026-06-12T09:07:30.000000Z")

    def test_offset_normalises_to_utc(self):
        offset = dt.datetime(
            2026, 6, 12, 11, 7, 30, 394151, tzinfo=dt.timezone(dt.timedelta(hours=2))
        )
        self.assertEqual(ids.canonical_instant(offset), "2026-06-12T09:07:30.394151Z")

    def test_naive_datetime_refused(self):
        with self.assertRaises(ids.IdentityError):
            ids.canonical_instant(dt.datetime(2026, 6, 12, 9, 7, 30))

    def test_datetime_inside_an_identity_is_canonicalised(self):
        aware = dt.datetime(2026, 6, 12, 9, 7, 30, 394151, tzinfo=dt.timezone.utc)
        self.assertEqual(ids.canonical_json({"t": aware}), '{"t":"2026-06-12T09:07:30.394151Z"}')


class TestIdShape(unittest.TestCase):
    def test_every_prefix_yields_prefix_plus_twelve_hex(self):
        for prefix in sorted(ids.PREFIXES):
            with self.subTest(prefix=prefix):
                value = ids.node_id(prefix, {"k": "v"})
                self.assertRegex(value, ID_SHAPE)
                self.assertTrue(value.startswith(f"{prefix}_"))
                self.assertEqual(len(value), len(prefix) + 1 + 12)

    def test_the_six_prefixes_are_exactly_SS8_2s_table(self):
        self.assertEqual(ids.PREFIXES, frozenset({"rec", "obs", "edg", "fnd", "map", "hyp"}))

    def test_unknown_prefix_refused(self):
        with self.assertRaises(ids.IdentityError):
            ids.node_id("claim", {"k": "v"})

    def test_empty_identity_refused(self):
        """An id derived from nothing would be the same id for every node of its kind."""
        with self.assertRaises(ids.IdentityError):
            ids.node_id("obs", {})


class TestContentDigest(unittest.TestCase):
    """The whole-digest form the prompt hash and the contract-set hash (T06) use."""

    def test_full_sha256_hex(self):
        digest = ids.content_digest({"a": 1})
        self.assertEqual(len(digest), 64)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_the_id_is_its_first_twelve_characters(self):
        identity = {"k": "v"}
        self.assertTrue(ids.node_id("obs", identity).endswith(ids.content_digest(identity)[:12]))


if __name__ == "__main__":
    unittest.main()
