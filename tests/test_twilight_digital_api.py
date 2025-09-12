import unittest
from copy import deepcopy
from twilight_digital_api import create_app
from datetime import datetime, timezone, timedelta

# Simple in-memory mock of a Mongo-like API
class _InsertOneResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id

class _DeleteResult:
    def __init__(self, deleted_count):
        self.deleted_count = deleted_count

class _UpdateResult:
    def __init__(self, matched_count, modified_count):
        self.matched_count = matched_count
        self.modified_count = modified_count

class FakeCollection:
    def __init__(self):
        # store by _id to mirror app behavior
        self._docs_by_id = {}
        self._indexes = []

    def create_index(self, keys, unique=False):
        # no-op, but record for completeness
        self._indexes.append((tuple(keys), unique))
        return "_fake_index"

    def insert_one(self, doc):
        doc = deepcopy(doc)
        _id = doc.get("_id")
        if _id is None:
            raise ValueError("Missing _id")
        if _id in self._docs_by_id:
            raise ValueError("Duplicate key error")
        self._docs_by_id[_id] = doc
        return _InsertOneResult(_id)

    def find_one(self, filter_dict):
        for d in self._docs_by_id.values():
            ok = True
            for k, v in filter_dict.items():
                if d.get(k) != v:
                    ok = False
                    break
            if ok:
                return deepcopy(d)
        return None

    def find(self, filter_dict=None, limit=None):
        filter_dict = filter_dict or {}
        results = []
        for d in self._docs_by_id.values():
            ok = True
            for k, v in filter_dict.items():
                if isinstance(v, dict) and '$gte' in v and '$lte' in v:
                    if d.get(k) < v['$gte'] or d.get(k) > v['$lte']:
                        ok = False
                        break
                else:
                    if d.get(k) != v:
                        ok = False
                        break
            if ok:
                results.append(deepcopy(d))
        if limit is not None:
            results = results[:limit]
        # Return an iterable consistent with PyMongo's cursor
        for item in results:
            yield item

    def update_one(self, filter_dict, update_dict):
        doc = self.find_one(filter_dict)
        if not doc:
            return _UpdateResult(0, 0)
        # Apply only $set updates
        sets = update_dict.get("$set", {})
        updated = dict(doc)
        updated.update(sets)
        self._docs_by_id[updated["_id"]] = updated
        return _UpdateResult(1, 1)

    def delete_one(self, filter_dict):
        # locate by filter, then delete by _id
        doc = self.find_one(filter_dict)
        if not doc:
            return _DeleteResult(0)
        del self._docs_by_id[doc["_id"]]
        return _DeleteResult(1)

class FakeMongoDB:
    def __init__(self):
        self._collections = {}

    def __getitem__(self, name):
        if name not in self._collections:
            self._collections[name] = FakeCollection()
        return self._collections[name]

class TestTwilightDigitalAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # create app with in-memory fake Mongo
        fake_db = FakeMongoDB()
        test_app = create_app(mdb=fake_db)
        cls.client = test_app.test_client()

    def _crud_cycle(self, collection, create_payload, update_payload, id_field, invalid_enum=None):
        # Create
        resp = self.client.post(f"/{collection}", json=create_payload)
        self.assertEqual(resp.status_code, 201, f"Create failed for {collection}: {resp.data}")
        created = resp.get_json()
        self.assertIn(id_field, created)
        entity_id = created[id_field]

        # List
        resp = self.client.get(f"/{collection}")
        self.assertEqual(resp.status_code, 200)
        items = resp.get_json()
        self.assertTrue(any(i[id_field] == entity_id for i in items))

        # Get by id
        resp = self.client.get(f"/{collection}/{entity_id}")
        self.assertEqual(resp.status_code, 200)
        fetched = resp.get_json()
        self.assertEqual(fetched[id_field], entity_id)

        # Patch
        resp = self.client.patch(f"/{collection}/{entity_id}", json=update_payload)
        self.assertEqual(resp.status_code, 200)
        updated = resp.get_json()
        for k, v in update_payload.items():
            self.assertEqual(updated.get(k), v)

        # ID immutable check
        resp = self.client.patch(f"/{collection}/{entity_id}", json={id_field: "SHOULD_NOT_CHANGE"})
        self.assertEqual(resp.status_code, 400)

        # Delete
        resp = self.client.delete(f"/{collection}/{entity_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json().get("deleted_id"), entity_id)

        # Get after delete
        resp = self.client.get(f"/{collection}/{entity_id}")
        self.assertEqual(resp.status_code, 404)

        # Optional invalid enum validation case on create
        if invalid_enum:
            bad_payload = dict(create_payload)
            bad_payload.update(invalid_enum)
            resp = self.client.post(f"/{collection}", json=bad_payload)
            self.assertEqual(resp.status_code, 400)

    def test_channels_crud(self):
        self._crud_cycle(
            "channels",
            {
                "title": "Primary",
                "description": "Desc",
                "thumbnail_url": None,
                "creator_id": "12345",
                "publishing_type": "Auto_Fanout",
                "content_maturity": "PG13",
            },
            {"description": "Updated"},
            id_field="channel_id",
        )

    def test_users_crud(self):
        self._crud_cycle(
            "users",
            {"email": "alpha@example.com", "screen_name": "alpha", "role": "Subscriber", "content_maturity": "G"},
            {"screen_name": "beta"},
            id_field="user_id",
        )

    def test_contacts_crud_and_enum_validation(self):
        # Valid create
        self._crud_cycle(
            "contacts",
            {"user_id": "U1", "contact_type": "Phone", "data": "555-555"},
            {"data": "555-000"},
            id_field="contact_id",
            invalid_enum={"contact_type": "NotAType"},
        )

    def test_credential_configs_crud_and_enum_validation(self):
        # Create a user first since credential_configs require user_id
        user_email = "cred_user@example.com"
        user = self.client.post(
            "/users",
            json={"email": user_email, "screen_name": "cred_user", "role": "Subscriber", "content_maturity": "G"}
        ).get_json()

        self._crud_cycle(
            "credential_configs",
            {"user_id": user["user_id"], "email": user_email, "credential_type": "OAuth",
             "encrypted_credential": "XXX"},
            {"encrypted_credential": "YYY"},
            id_field="credential_config_id",
            invalid_enum={"credential_type": "NotAType"},
        )

    def test_events_crud(self):
        ch = self.client.post(
            "/channels",
            json={
                "title": "Ch",
                "description": "d",
                "thumbnail_url": None,
                "creator_id": "1234",
                "publishing_type": "Auto_Fanout",
                "content_maturity": "PG13",
            },
        ).get_json()
        tier = self.client.post(
            "/subscription_tiers",
            json={"title": "T", "description": "d", "thumbnail_url": None, "monthly_price": 1.0, "tier_ordinal": 1},
        ).get_json()
        self._crud_cycle(
            "events",
            {
                "channel_id": ch["channel_id"],
                "date_time": "2025-01-01T00:00:00Z",
                "tier_ordinal": tier["tier_ordinal"],
                "title": "E",
                "body": "B",
                "thumbnail_url": None,
                "content_url": None,
                "content_maturity": "PG13",
            },
            {"body": "Up"},
            id_field="event_id",
        )

    def test_subscription_tiers_crud(self):
        self._crud_cycle(
            "subscription_tiers",
            {"title": "Tier 1", "description": "D", "thumbnail_url": None, "monthly_price": 9.99, "tier_ordinal": 1},
            {"monthly_price": 19.99},
            id_field="subscription_tier_id",
        )

    def test_subscriptions_crud(self):
        # user acts as subscriber; create user and tier, then subscribe
        ch = self.client.post(
            "/channels",
            json={
                "title": "C",
                "description": "d",
                "thumbnail_url": None,
                "creator_id": "1234",
                "publishing_type": "Auto_Fanout",
                "content_maturity": "PG13",
            },
        ).get_json()
        user = self.client.post(
            "/users",
            json={"email": "u1@example.com", "screen_name": "u1", "role": "Subscriber", "content_maturity": "G"},
        ).get_json()
        tier = self.client.post(
            "/subscription_tiers",
            json={"title": "T", "description": "d", "thumbnail_url": None, "monthly_price": 1.0, "tier_ordinal": 1},
        ).get_json()
        self._crud_cycle(
            "subscriptions",
            {"user_id": user["user_id"], "channel_id": ch["channel_id"], "subscription_tier_id": tier["subscription_tier_id"]},
            {"subscription_tier_id": tier["subscription_tier_id"]},
            id_field="subscription_id",
        )

    def test_stripe_payment_agreements_crud(self):
        user = self.client.post(
            "/users",
            json={"email": "billto@example.com", "screen_name": "billto",
                  "role": "Subscriber", "content_maturity": "G"},
        ).get_json()
        self._crud_cycle(
            "stripe_payment_agreements",
            {
                "user_id": user["user_id"],
                "stripe_subscription_id": "stripe_sub_1",
                "stripe_customer_id": "cust_1",
                "stripe_product_id": "prod_1",
            },
            {"stripe_product_id": "prod_2"},
            id_field="stripe_payment_agreement_id",
        )

    def test_user_notes_one_to_many_and_crud(self):
        # create user
        user = self.client.post(
            "/users",
            json={"email": "u2@example.com", "screen_name": "u2", "role": "Subscriber", "content_maturity": "G"},
        ).get_json()

        # create two notes for same user
        n1 = self.client.post("/user_notes", json={"user_id": user["user_id"], "text": "first"}).get_json()
        n2 = self.client.post("/user_notes", json={"user_id": user["user_id"], "text": "second"}).get_json()
        self.assertIn("note_id", n1)
        self.assertIn("note_id", n2)
        self.assertNotEqual(n1["note_id"], n2["note_id"])

        # list should include both notes (global list limited to 100)
        notes = self.client.get("/user_notes").get_json()
        user_notes = [n for n in notes if n["user_id"] == user["user_id"]]
        self.assertTrue(any(n["note_id"] == n1["note_id"] for n in user_notes))
        self.assertTrue(any(n["note_id"] == n2["note_id"] for n in user_notes))

        # get, patch, delete for one note using common helper
        self._crud_cycle(
            "user_notes",
            {"user_id": user["user_id"], "text": "third"},
            {"text": "third-updated"},
            id_field="note_id",
        )

    def test_get_user_by_email_valid_and_invalid(self):
        # Create a user
        email = "lookup_user@example.com"
        created = self.client.post(
            "/users",
            json={"email": email, "screen_name": "lookup_user", "role": "Subscriber", "content_maturity": "G"},
        ).get_json()
        self.assertIn("user_id", created)

        # Valid lookup
        resp = self.client.get(f"/users/by_email/{email}")
        self.assertEqual(resp.status_code, 200)
        user = resp.get_json()
        self.assertEqual(user["email"], email)
        self.assertEqual(user["user_id"], created["user_id"])

        # Invalid lookup (not found)
        resp = self.client.get("/users/by_email/notfound@example.com")
        self.assertEqual(resp.status_code, 404)

    def test_get_credential_configs_by_email_valid_and_empty(self):
        # Seed a user and two credential configs with same email
        email = "creds_lookup@example.com"
        user = self.client.post(
            "/users",
            json={"email": email, "screen_name": "creds_user", "role": "Subscriber", "content_maturity": "G"},
        ).get_json()

        c1 = self.client.post(
            "/credential_configs",
            json={"user_id": user["user_id"], "email": email, "credential_type": "OAuth", "encrypted_credential": "AAA"},
        ).get_json()
        c2 = self.client.post(
            "/credential_configs",
            json={"user_id": user["user_id"], "email": email, "credential_type": "Email_2FA", "encrypted_credential": "BBB"},
        ).get_json()
        self.assertIn("credential_config_id", c1)
        self.assertIn("credential_config_id", c2)
        self.assertNotEqual(c1["credential_config_id"], c2["credential_config_id"])

        # Valid lookup should return both
        resp = self.client.get(f"/credential_configs/by_email/{email}")
        self.assertEqual(resp.status_code, 200)
        items = resp.get_json()
        self.assertTrue(isinstance(items, list))
        types = sorted([i["credential_type"] for i in items])
        self.assertEqual(types, ["Email_2FA", "OAuth"])

        # Empty result for an email with no configs (still 200, empty list)
        resp = self.client.get("/credential_configs/by_email/none@example.com")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), [])

class AuditLogsRouteTests(unittest.TestCase):
    def setUp(self):
        self.mdb = FakeMongoDB()
        self.app = create_app(self.mdb)
        self.client = self.app.test_client()

        # Seed audit_logs
        coll = self.mdb["audit_logs"]
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        # In-range for user A
        coll.insert_one({
            "_id": "1",
            "audit_log_id": "1",
            "user_id": "userA",
            "action_type": "Created",
            "collection": "users",
            "record_id": "ra",
            "datetime": base + timedelta(days=1),
        })
        coll.insert_one({
            "_id": "2",
            "audit_log_id": "2",
            "user_id": "userA",
            "action_type": "Updated",
            "collection": "users",
            "record_id": "rb",
            "datetime": base + timedelta(days=2),
        })
        # Out-of-range for user A
        coll.insert_one({
            "_id": "3",
            "audit_log_id": "3",
            "user_id": "userA",
            "action_type": "Deleted",
            "collection": "users",
            "record_id": "rc",
            "datetime": base + timedelta(days=10),
        })
        # Different user
        coll.insert_one({
            "_id": "4",
            "audit_log_id": "4",
            "user_id": "userB",
            "action_type": "Created",
            "collection": "users",
            "record_id": "rd",
            "datetime": base + timedelta(days=1),
        })

    def test_get_audit_logs_by_user_id_valid_range(self):
        start = "2024-01-01T00:00:00Z"
        end = "2024-01-05T00:00:00Z"
        resp = self.client.get(f"/audit_logs/by_user_id/userA?start_date={start}&end_date={end}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        # Expect only the two in-range docs for userA
        self.assertEqual(len(data), 2)
        returned_ids = {d["audit_log_id"] for d in data}
        self.assertSetEqual(returned_ids, {"1", "2"})

    def test_get_audit_logs_by_user_id_missing_params(self):
        resp = self.client.get("/audit_logs/by_user_id/userA?start_date=2024-01-01T00:00:00Z")
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("start_date and end_date are required", data["error"])

    def test_get_audit_logs_by_user_id_invalid_date_format(self):
        resp = self.client.get("/audit_logs/by_user_id/userA?start_date=not-a-date&end_date=2024-01-05")
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("Invalid datetime format", data["error"])

    def test_get_audit_logs_by_user_id_end_before_start(self):
        resp = self.client.get("/audit_logs/by_user_id/userA?start_date=2024-01-05T00:00:00Z&end_date=2024-01-01T00:00:00Z")
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("end_date must be greater", data["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
