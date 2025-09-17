import os
import random
import string
import time
from datetime import datetime, timezone, timedelta
import json
import requests

BASE_URL = os.getenv("TWILIGHT_DIGITAL_API_BASE_URL", "http://localhost:8080").rstrip("/")
DEFAULT_USER_EMAIL = "jklappenbach@gmail.com"
user_id = ""

# How many to create
NUM_CREATORS = 10
CHANNELS_PER_CREATOR = 1  # create exactly one per user per request
EVENTS_PER_CHANNEL = 10
DEFAULT_USER_SUBS = 12

# Simple data helpers
CREATOR_ROLE = "Creator"
CONTENT_MATURITIES = ["G", "PG13", "NC17"]
PUBLISHING_TYPES = ["Auto_Fanout", "Lazy_Loading"]

THUMB_EXAMPLE = "https://picsum.photos/seed/{seed}/400/300"
CONTENT_EXAMPLE = "https://example.com/content/{seed}"

session = requests.Session()
# Optionally add a user header for audit logging transparency

def iso_now(offset_minutes=0):
    dt = datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)
    # ISO-8601 with Z
    return dt.isoformat().replace("+00:00", "Z")

def rand_word(min_len=5, max_len=10):
    n = random.randint(min_len, max_len)
    return "".join(random.choices(string.ascii_letters, k=n)).capitalize()

def rand_sentence(words=5, max_word_len=10):
    return " ".join(rand_word(3, max_word_len) for _ in range(words))

def post(path, payload, expect_status=(200,201)):
    url = f"{BASE_URL}{path}"
    r = session.post(url, data=json.dumps(payload))
    if r.status_code not in expect_status:
        raise RuntimeError(f"POST {path} failed: {r.status_code} {r.text}")
    return r.json()

def get(path, expect_status=(200,201)):
    url = f"{BASE_URL}{path}"
    r = session.get(url)
    if r.status_code not in expect_status:
        raise RuntimeError(f"GET {path} failed: {r.status_code}, {r.text}")
    return r.json()

def get_default_user():
    default_user = get(f"/users/by_email/{DEFAULT_USER_EMAIL}")
    return default_user.get("user_id")

def create_user(ix):
    seed = f"user{ix:03d}-{rand_word()}"
    email = f"{seed.lower()}@example.com"
    payload = {
        "email": email,
        "screen_name": seed,
        "role": CREATOR_ROLE,
        "content_maturity": random.choice(CONTENT_MATURITIES),
        "thumbnail_url": THUMB_EXAMPLE.format(seed=seed),
    }
    return post("/users", payload, expect_status=(201,))

def create_channel_for_user(user, ix):
    seed = f"ch{ix:03d}-{rand_word()}"
    payload = {
        "title": f"{rand_word()} {rand_word()} Channel",
        "description": f"{rand_sentence(8)} about {rand_word()}",
        "thumbnail_url": THUMB_EXAMPLE.format(seed=seed),
        "creator_id": user["user_id"],
        "publishing_type": random.choice(PUBLISHING_TYPES),
        "content_maturity": random.choice(CONTENT_MATURITIES),
    }
    return post("/channels", payload, expect_status=(201,))

def create_subscription_tier(channel, ix):
    seed = f"tier{ix:03d}-{rand_word()}"
    payload = {
        "title": f"{rand_word()} Tier",
        "description": f"Access level for {channel['title']}",
        "thumbnail_url": THUMB_EXAMPLE.format(seed=seed),
        "monthly_price": str(random.choice([3,5,10,15,20])),  # API accepts string
        "tier_ordinal": "1",  # lowest tier
    }
    return post("/subscription_tiers", payload, expect_status=(201,))

def create_subscription(user_id, channel, subscription_tier_id):
    payload = {
        "user_id": user_id,
        "channel_id": channel["channel_id"],
        "channel_title": channel.get("title") or "",
        "channel_thumbnail_url": channel.get("thumbnail_url") or THUMB_EXAMPLE.format(seed=channel["channel_id"]),
        "subscription_tier_id": subscription_tier_id,
    }
    return post("/subscriptions", payload, expect_status=(201,))


def create_event(channel, ev_index):
    seed = f"ev-{channel['channel_id']}-{ev_index:04d}"
    payload = {
        "channel_id": channel["channel_id"],
        "date_time": iso_now(offset_minutes=-(10000 - ev_index)),  # spread out the dates
        "tier_ordinal": "1",
        "title": f"{rand_word()} {rand_word()} #{ev_index}",
        "body": f"{rand_sentence(12)}",
        "thumbnail_url": THUMB_EXAMPLE.format(seed=seed),
        "content_url": CONTENT_EXAMPLE.format(seed=seed),
        "content_maturity": random.choice(CONTENT_MATURITIES),
    }
    return post("/events", payload, expect_status=(201,))

def create_feed_record(user_id, channel, event):
    payload = {
        "event_id": event["event_id"],
        "user_id": user_id,
        "date_time": event["date_time"],
        "title": event["title"],
        "body": event["body"],
        "thumbnail_url": event["thumbnail_url"],
        "content_url": event["content_url"],
        "content_maturity": event["content_maturity"],
        "channel_title": channel["title"],
        "channel_id": channel["channel_id"],
        "viewed": "false",
    }
    return post("/feeds", payload, expect_status=(201,))

def main():
    random.seed()  # system entropy

    created = {
        "users": [],
        "channels": [],
        "subscription_tiers": [],
        "subscriptions_for_default_user": [],
        "events_by_channel": {},  # channel_id -> [event_ids]
        "feeds_for_default_user": [],  # event_ids
    }

    print(f"Using API base URL: {BASE_URL}")

    # Timing helpers
    def _extract_id(obj):
        # Try to find any *_id field to display
        if isinstance(obj, dict):
            for k in obj.keys():
                if k.endswith("_id"):
                    return obj[k]
        return None

    timings = {
        "users": 0.0,
        "channels": 0.0,
        "subscription_tiers": 0.0,
        "subscriptions": 0.0,
        "events": 0.0,
        "feeds": 0.0,
    }

    def time_call(key, label, func, *args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        dur = time.perf_counter() - start
        timings[key] += dur
        ent_id = _extract_id(result)
        if ent_id:
            print(f"{label} ({ent_id}) created in {dur:.3f}s")
        else:
            print(f"{label} created in {dur:.3f}s")
        return result

    user_id = get_default_user()
    session.headers.update({"Content-Type": "application/json", "X-User-Id": user_id})
    total_start = time.perf_counter()

    # 1) Create creators (users)
    for i in range(NUM_CREATORS):
        u = time_call("users", "User", create_user, i)
        created["users"].append(u)
        if (i + 1) % 10 == 0:
            print(f"Created users: {i+1}/{NUM_CREATORS}")


    # 2) Create one channel per user + 1 subscription tier per channel
    for i, u in enumerate(created["users"]):
        ch = time_call("channels", "Channel", create_channel_for_user, u, i)
        created["channels"].append(ch)
        tier = time_call("subscription_tiers", "SubscriptionTier", create_subscription_tier, ch, i)
        created["subscription_tiers"].append({
            "channel_id": ch["channel_id"],
            "subscription_tier_id": tier["subscription_tier_id"],
        })
        if (i + 1) % 10 == 0:
            print(f"Created channels/tiers: {i+1}/{len(created['users'])}")

    # Map channel_id -> tier_id
    tier_by_channel = {t["channel_id"]: t["subscription_tier_id"] for t in created["subscription_tiers"]}

    # 3) Subscribe default user to 12 random distinct channels
    chosen_channels = random.sample(created["channels"], k=min(DEFAULT_USER_SUBS, len(created["channels"])))
    for ch in chosen_channels:
        sub = time_call(
            "subscriptions",
            "Subscription",
            create_subscription,
            user_id,
            ch,
            tier_by_channel[ch["channel_id"]],
        )
        created["subscriptions_for_default_user"].append(sub)
    print(f"Created {len(created['subscriptions_for_default_user'])} subscriptions for default user")

    # 4) Create events for each channel
    # 5) If channel is in subscribed set, create feed records for the default user
    subscribed_channel_ids = {s["channel_id"] for s in created["subscriptions_for_default_user"]}

    total_channels = len(created["channels"])
    for idx, ch in enumerate(created["channels"], start=1):
        ch_id = ch["channel_id"]
        created["events_by_channel"][ch_id] = []
        for ev_i in range(1, EVENTS_PER_CHANNEL + 1):
            ev = time_call("events", "Event", create_event, ch, ev_i)
            created["events_by_channel"][ch_id].append(ev["event_id"])
            if ch_id in subscribed_channel_ids:
                fr = time_call("feeds", "FeedRecord", create_feed_record, user_id, ch, ev)
                created["feeds_for_default_user"].append(fr["field_id"] if "field_id" in fr else ev["event_id"])
        if idx % 5 == 0 or idx == total_channels:
            print(f"Created events for channels: {idx}/{total_channels}")

    # Persist IDs for reuse
    out_path = "seed_output.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(created, f, indent=2)
    # Print per-entity-type timing summary
    print("Timing summary per entity type (seconds):")
    for key, total_sec in timings.items():
        print(f"  {key}: {total_sec:.3f}s")

    total_elapsed = time.perf_counter() - total_start
    print(f"Total seeding time: {total_elapsed:.3f}s")

    print(f"Done. Wrote IDs and mappings to {out_path}")
    print(f"Summary: users={len(created['users'])}, channels={len(created['channels'])}, "
          f"subs={len(created['subscriptions_for_default_user'])}, "
          f"events={sum(len(v) for v in created['events_by_channel'].values())}, "
          f"feeds={len(created['feeds_for_default_user'])}")

if __name__ == "__main__":
    main()
