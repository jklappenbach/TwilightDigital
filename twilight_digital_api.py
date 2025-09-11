from flask import Flask, jsonify, request, json
from uuid import uuid4
import os
from pymongo import MongoClient, ASCENDING
from datetime import datetime, timezone
import logging
from pathlib import Path


def create_app(mdb=None):
    app = Flask(__name__)

    # Configure logging
    log_level_name = os.getenv("TWILIGHT_DIGITAL_LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    app.logger.setLevel(log_level)
    if not app.logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(log_level)
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")
        handler.setFormatter(formatter)
        app.logger.addHandler(handler)

    # If no database provided (e.g., production), connect to real MongoDB
    if mdb is None:
        mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        mongo_db_name = os.getenv("MONGODB_DB", "twilight_digital")
        mongo_client = MongoClient(mongo_uri)
        mdb = mongo_client[mongo_db_name]

    # Enum constraints where the definition includes them
    CONTACT_TYPES = ["Phone", "Email_Address", "Push_Notification"]
    CREDENTIAL_TYPES = ["OAuth", "Authenticator_2FA", "Email_2FA", "SMS_2FA"]
    ROLES = ["Creator", "Subscriber", "Admin", "Support"]
    PUBLISHING_TYPES = ["Auto_Fanout", "Lazy_Loading"]
    CONTENT_MATURITY_TYPES = ["G", "PG13", "NC17"]
    ACTION_TYPES = ["Created", "Updated", "Deleted"]

    # Entity registry describing endpoint names, id fields, and validations
    ENTITIES = {
        "channels": {
            "id_field": "channel_id",
            "enums": { "publishing_type": PUBLISHING_TYPES, "content_maturity": CONTENT_MATURITY_TYPES },
            "required": ["title", "description", "thumbnail_url", "creator_id", "publishing_type", "content_maturity"],
            "optional": [],
        },
        "users": {
            "id_field": "user_id",
            "enums": { "role": ROLES, "content_maturity": CONTENT_MATURITY_TYPES  },
            "required": ["email", "screen_name", "role", "content_maturity"],
            "optional": ["thumbnail_url"],
        },
        "user_notes": {
            "id_field": "note_id",  # no explicit admin_id in definition; make a synthetic one
            "enums": {},
            "required": ["note_id", "user_id", "text"],
            "optional": [],
        },
        "contacts": {
            "id_field": "contact_id",
            "enums": {
                "contact_type": CONTACT_TYPES,
            },
            "required": ["user_id", "contact_type", "data"],
            "optional": [],
        },
        "credential_configs": {
            "id_field": "credential_config_id",
            "enums": {
                "credential_type": CREDENTIAL_TYPES,
            },
            "required": ["user_id", "email", "credential_type", "encrypted_credential"],
            "optional": [],
        },
        "events": {
            "id_field": "event_id",
            "enums": { "content_maturity": CONTENT_MATURITY_TYPES },
            "required": ["channel_id", "date_time", "tier_ordinal", "title", "body", "thumbnail_url", "content_url", "content_maturity"],
            "optional": [],
        },
        # event_user is the feed for each user, where event IDs will be stored as records.
        # These records track whether they've been viewed, and can be deleted.
        "event_user": {
            "id_field": "event_user_id",
            "enums": {},
            "required": ["event_id", "user_id"],
            "optional": ["viewed"],
        },
        "subscription_tiers": {
            "id_field": "subscription_tier_id",
            "enums": {},
            "required": ["title", "description", "thumbnail_url", "monthly_price", "tier_ordinal"],
            "optional": [],
        },
        "subscriptions": {
            "id_field": "subscription_id",
            "enums": {},
            "required": ["user_id", "channel_id", "subscription_tier_id"],
            "optional": [],
        },
        "stripe_payment_agreements": {
            "id_field": "stripe_payment_agreement_id",
            "enums": {},
            "required": ["user_id", "stripe_subscription_id", "stripe_customer_id", "stripe_product_id"],
            "optional": [],
        },
        "audit_logs": {
            "id_field": "audit_log_id",
            "enums": { "action_type": ACTION_TYPES },
            "required": ["collection", "record_id", "action_type", "user_id", "datetime"],
        }
    }

    def _entity_config(collection_name):
        if collection_name not in ENTITIES:
            return None
        cfg = ENTITIES[collection_name]
        # Resolve real id field (synthesized if not explicitly present)
        id_field = cfg.get("id_field")
        if not id_field:
            id_field = cfg.get("synthetic_id_field")
        return {
            "id_field": id_field,
            "enums": cfg.get("enums", {}),
            "required": cfg.get("required", []),
            "optional": cfg.get("optional", []),
        }

    # Ensure unique indexes on each entity's id field
    for _collection_name, cfg in ENTITIES.items():
        resolved_id_field = cfg.get("id_field") or cfg.get("synthetic_id_field")
        if resolved_id_field:
            try:
                mdb[_collection_name].create_index([(resolved_id_field, ASCENDING)], unique=True)
            except Exception:
                # Allow mocks that do not implement create_index
                pass

    # Also index fields for quick lookup
    try:
        mdb["users"].create_index([("email", ASCENDING)], unique=True)
    except Exception:
        pass
    try:
        mdb["credential_configs"].create_index([("email", ASCENDING)], unique=False)
    except Exception:
        pass
    try:
        mdb["channels"].create_index([("creator_id", ASCENDING)], unique=False)
    except Exception:
        pass
    try:
        mdb["events"].create_index([("channel_id", ASCENDING)], unique=False)
    except Exception:
        pass
    try:
        mdb["event_user"].create_index([("user_id", ASCENDING)], unique=False)
    except Exception:
        pass
    try:
        mdb["audit_log"].create_index([("user_id", ASCENDING)], unique=False)
    except Exception:
        pass

    def _generate_id():
        return str(uuid4())

    def _validate_enums(enums, payload):
        for field, allowed in enums.items():
            if field in payload and payload[field] not in allowed:
                return f"{field} must be one of: {', '.join(allowed)}"
        return None

    def _validate_required(required_fields, id_field, payload, is_create):
        # Require presence of all non-ID fields on create. Values may be None; only key presence is enforced.
        if not is_create:
            return None
        missing = [f for f in required_fields if f != id_field and f not in payload]
        if missing:
            return f"Missing required fields: {', '.join(missing)}"
        return None

    def _validate_no_extra_fields(allowed_fields, id_field, payload, is_create):
        # Enforce strict allowlist: only required + optional + id_field
        keys = set(payload.keys())
        if not is_create:
            # On update, id is not allowed in the payload
            if id_field in keys:
                return f"{id_field} is immutable"
        extras = keys - set(allowed_fields)
        if extras:
            return f"Unknown fields: {', '.join(sorted(extras))}"
        return None

    def _validate_and_prepare_payload(collection_name, payload, is_create):
        cfg = _entity_config(collection_name)
        if not cfg:
            return "Unknown collection", None
        id_field = cfg["id_field"]
        enums = cfg["enums"]
        required_fields = cfg["required"]
        optional_fields = cfg["optional"]

        if not isinstance(payload, dict):
            return "Invalid JSON payload", None

        allowed_fields = set(required_fields) | set(optional_fields) | {id_field}

        unknown_err = _validate_no_extra_fields(allowed_fields, id_field, payload, is_create)
        if unknown_err:
            return unknown_err, None

        doc = dict(payload)
        if is_create:
            if id_field not in doc or not doc[id_field]:
                doc[id_field] = _generate_id()
        else:
            if id_field in doc:
                return f"{id_field} is immutable", None

        req_err = _validate_required(required_fields, id_field, doc, is_create)
        if req_err:
            return req_err, None

        enum_err = _validate_enums(enums, doc)
        if enum_err:
            return enum_err, None

        return None, doc

    def _strip_mongo_id(doc):
        if not doc:
            return None
        cleaned = dict(doc)
        cleaned.pop("_id", None)
        return cleaned

    # ---- OpenAPI generation ----
    def _entity_to_schema(entity_name: str, cfg: dict, for_update: bool = False) -> dict:
        """
        Translate ENTITIES entry into an OpenAPI schema.
        For updates, we omit 'required' to allow partial PATCH documents.
        """
        id_field = cfg.get("id_field")
        required_fields = list(cfg.get("required", []))
        optional_fields = list(cfg.get("optional", []))
        enums = cfg.get("enums", {})

        props = {}
        for field in sorted(set(required_fields + optional_fields + [id_field])):
            field_schema = {"type": "string"}
            if field in enums:
                field_schema["enum"] = list(enums[field])
            props[field] = field_schema

        schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": props,
        }
        if not for_update:
            # For create/read schemas include required list (excluding None/empty)
            req = [f for f in required_fields if f]
            if id_field and id_field not in req:
                # ID may be generated if omitted on create, but it's always present in read responses.
                # We'll not force it on create; responses will include it.
                pass
            if req:
                schema["required"] = req
        return schema

    def _build_openapi_document() -> dict:
        # Base metadata
        info = {
            "title": "Twilight Digital API",
            "version": "1.0.0",
            "description": "OpenAPI 3.0 specification generated from the API's entity registry and routes.",
        }

        servers = []
        external_url = app.config.get("EXTERNAL_URL") or os.getenv("TWILIGHT_DIGITAL_API_BASE_URL")
        if external_url:
            servers.append({"url": external_url.rstrip("/")})
        else:
            servers.append({"url": "http://localhost:8080"})

        # Components: common error and per-entity schemas
        components = {"schemas": {}}
        components["schemas"]["Error"] = {
            "type": "object",
            "properties": {"error": {"type": "string"}},
            "required": ["error"],
            "additionalProperties": False,
        }

        # Create read/create schemas and update schemas per entity
        for name, cfg in ENTITIES.items():
            read_schema_name = name
            create_schema_name = read_schema_name  # same structure; required applies
            update_schema_name = f"{read_schema_name}_update"

            components["schemas"][create_schema_name] = _entity_to_schema(name, cfg, for_update=False)
            components["schemas"][update_schema_name] = _entity_to_schema(name, cfg, for_update=True)

        paths = {}

        # CRUD paths per entity
        for name, cfg in ENTITIES.items():
            id_field = cfg.get("id_field")
            read_schema_name = name
            update_schema_name = f"{read_schema_name}_update"

            # Collection path
            paths[f"/{name}"] = {
                "get": {
                    "summary": f"List {name}",
                    "operationId": f"list_{name}",
                    "responses": {
                        "200": {
                            "description": "List of items",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"$ref": f"#/components/schemas/{read_schema_name}"},
                                    }
                                }
                            },
                        },
                        "500": {"description": "Server error",
                                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    },
                },
                "post": {
                    "summary": f"Create {read_schema_name}",
                    "operationId": f"create_{read_schema_name.lower()}",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": f"#/components/schemas/{read_schema_name}"}
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "Created",
                            "content": {
                                "application/json": {"schema": {"$ref": f"#/components/schemas/{read_schema_name}"}}},
                        },
                        "400": {"description": "Validation error",
                                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    },
                },
            }

            # Item path
            paths[f"/{name}/{{item_id}}"] = {
                "parameters": [
                    {
                        "name": "item_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                        "description": f"{id_field}",
                    }
                ],
                "get": {
                    "summary": f"Get {read_schema_name}",
                    "operationId": f"get_{read_schema_name.lower()}",
                    "responses": {
                        "200": {"description": "OK", "content": {
                            "application/json": {"schema": {"$ref": f"#/components/schemas/{read_schema_name}"}}}},
                        "404": {"description": "Not found",
                                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    },
                },
                "patch": {
                    "summary": f"Update {read_schema_name}",
                    "operationId": f"update_{read_schema_name.lower()}",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {"schema": {"$ref": f"#/components/schemas/{update_schema_name}"}}},
                    },
                    "responses": {
                        "200": {"description": "Updated", "content": {
                            "application/json": {"schema": {"$ref": f"#/components/schemas/{read_schema_name}"}}}},
                        "400": {"description": "Validation error",
                                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                        "404": {"description": "Not found",
                                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    },
                },
                "delete": {
                    "summary": f"Delete {read_schema_name}",
                    "operationId": f"delete_{read_schema_name.lower()}",
                    "responses": {
                        "200": {
                            "description": "Deleted",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"deleted_id": {"type": "string"}},
                                        "required": ["deleted_id"],
                                        "additionalProperties": False,
                                    }
                                }
                            },
                        },
                        "404": {"description": "Not found",
                                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    },
                },
            }

        # Extra lookups
        paths["/users/by_email/{email}"] = {
            "get": {
                "summary": "Get user by email",
                "operationId": "get_user_by_email",
                "parameters": [{"name": "email", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {
                    "200": {"description": "OK",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Users"}}}},
                    "404": {"description": "Not found",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                },
            }
        }
        paths["/credential_configs/by_email/{email}"] = {
            "get": {
                "summary": "List credential configs by email",
                "operationId": "get_credential_configs_by_email",
                "parameters": [{"name": "email", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {"type": "array",
                                           "items": {"$ref": "#/components/schemas/Credential_configs"}}
                            }
                        },
                    },
                },
            }
        }

        # Assemble OpenAPI document
        openapi = {
            "openapi": "3.0.3",
            "info": info,
            "servers": servers,
            "paths": paths,
            "components": components,
        }
        return openapi

    @app.route("/openapi.json", methods=["GET"])
    def openapi_spec():
        """
        Returns OpenAPI 3.0 JSON describing this API.
        """
        try:
            doc = _build_openapi_document()
            return jsonify(doc), 200
        except Exception as ex:
            app.logger.error("Failed to build OpenAPI document: %s", str(ex), exc_info=True)
            return jsonify(error="Failed to generate OpenAPI spec"), 500

    # Generic route factory
    def register_crud_routes(collection_name):
        cfg = _entity_config(collection_name)
        id_field = cfg["id_field"]
        collection = mdb[collection_name]

        # Make registration idempotent: skip if endpoints already exist
        collection_endpoint = f"{collection_name}_collection"
        item_endpoint = f"{collection_name}_item"
        if collection_endpoint in app.view_functions or item_endpoint in app.view_functions:
            app.logger.debug("Skipping duplicate route registration for %s", collection_name)
            return

        def collection_route():
            if request.method == "POST":
                payload = request.get_json(silent=True) or {}
                app.logger.info("POST /%s args payload=%s", collection_name, payload)
                err, doc = _validate_and_prepare_payload(collection_name, payload, is_create=True)
                if err:
                    app.logger.error("Validation error on POST /%s: %s", collection_name, err)
                    return jsonify(error=err), 400
                # Mirror logical id into _id for efficient lookups
                doc["_id"] = doc[id_field]
                try:
                    # Persist
                    collection.insert_one(doc)
                except Exception as e:
                    app.logger.error("Database insert error on POST /%s: %s", collection_name, str(e), exc_info=True)
                    return jsonify(error=str(e)), 400
                return jsonify(_strip_mongo_id(doc)), 201

            # GET list (no filters for simplicity; limit to 100)
            app.logger.info("GET /%s args query=%s", collection_name, dict(request.args))
            items = []
            try:
                cursor = collection.find({}, limit=100)
                for d in cursor:
                    items.append(_strip_mongo_id(d))
            except TypeError as e:
                app.logger.error("Database find signature error on GET /%s: %s. Falling back without limit kwarg.",
                                 collection_name, str(e), exc_info=True)
                try:
                    items = [_strip_mongo_id(d) for d in collection.find({})][:100]
                except Exception as e2:
                    app.logger.error("Database find error on GET /%s: %s", collection_name, str(e2), exc_info=True)
                    return jsonify(error=str(e2)), 500
            except Exception as e:
                app.logger.error("Database find error on GET /%s: %s", collection_name, str(e), exc_info=True)
                return jsonify(error=str(e)), 500
            return jsonify(items), 200

        app.add_url_rule(
            f"/{collection_name}",
            view_func=collection_route,
            methods=["GET", "POST"],
            endpoint=collection_endpoint,
        )

        def item_route(item_id: str):
            if request.method == "GET":
                app.logger.info("GET /%s/%s", collection_name, item_id)
                try:
                    doc = collection.find_one({id_field: item_id})
                except Exception as e:
                    app.logger.error("Database read error on GET /%s/%s: %s", collection_name, item_id, str(e),
                                     exc_info=True)
                    return jsonify(error=str(e)), 500
                if not doc:
                    app.logger.error("Not found on GET /%s/%s", collection_name, item_id)
                    return jsonify(error="Not found"), 404
                return jsonify(_strip_mongo_id(doc)), 200

            if request.method == "PATCH":
                payload = request.get_json(silent=True) or {}
                app.logger.info("PATCH /%s/%s args payload=%s", collection_name, item_id, payload)
                try:
                    existing = collection.find_one({id_field: item_id})
                except Exception as e:
                    app.logger.error("Database read error before PATCH /%s/%s: %s", collection_name, item_id, str(e),
                                     exc_info=True)
                    return jsonify(error=str(e)), 500
                if not existing:
                    app.logger.error("Not found on PATCH /%s/%s", collection_name, item_id)
                    return jsonify(error="Not found"), 404
                err, updated = _validate_and_prepare_payload(collection_name, payload, is_create=False)
                if err:
                    app.logger.error("Validation error on PATCH /%s/%s: %s", collection_name, item_id, err)
                    return jsonify(error=err), 400
                try:
                    collection.update_one({id_field: item_id}, {"$set": updated})
                except Exception as e:
                    app.logger.error("Database update error on PATCH /%s/%s: %s", collection_name, item_id, str(e),
                                     exc_info=True)
                    return jsonify(error=str(e)), 400
                try:
                    # Re-fetch to return the latest state
                    current = collection.find_one({id_field: item_id})
                except Exception as e:
                    app.logger.error("Database read-back error after PATCH /%s/%s: %s", collection_name, item_id,
                                     str(e), exc_info=True)
                    return jsonify(error=str(e)), 500
                return jsonify(_strip_mongo_id(current)), 200

            # DELETE
            app.logger.info("DELETE /%s/%s", collection_name, item_id)
            try:
                res = collection.delete_one({id_field: item_id})
            except Exception as e:
                app.logger.error("Database delete error on DELETE /%s/%s: %s", collection_name, item_id, str(e),
                                 exc_info=True)
                return jsonify(error=str(e)), 500
            deleted = getattr(res, "deleted_count", 1)
            if deleted == 0:
                app.logger.error("Not found on DELETE /%s/%s", collection_name, item_id)
                return jsonify(error="Not found"), 404
            return jsonify(deleted_id=item_id), 200

        app.add_url_rule(
            f"/{collection_name}/<string:item_id>",
            view_func=item_route,
            methods=["GET", "PATCH", "DELETE"],
            endpoint=item_endpoint,
        )

    @app.route("/", methods=["GET"])
    def index():
        # Render the home page using Jinja template
        from flask import render_template
        app.logger.info("GET / (render home) remote_addr=%s user_agent=%s", request.remote_addr,
                        request.headers.get("User-Agent"))
        return render_template("TwilightDigitalApiHome.html"), 200

    @app.route("/users/by_email/<path:email>", methods=["GET"])
    def get_user_by_email(email: str):
        app.logger.info("GET /users/by_email/%s", email)
        try:
            doc = mdb["users"].find_one({"email": email})
        except Exception as e:
            app.logger.error("Database read error on GET /users/by_email/%s: %s", email, str(e), exc_info=True)
            return jsonify(error=str(e)), 500
        if not doc:
            return jsonify(error="Not found"), 404
        return jsonify(_strip_mongo_id(doc)), 200

    # New: lookup credential_configs by email (may return multiple records)
    @app.route("/credential_configs/by_email/<path:email>", methods=["GET"])
    def get_credential_configs_by_email(email: str):
        app.logger.info("GET /credential_configs/by_email/%s", email)
        try:
            cursor = mdb["credential_configs"].find({"email": email}, limit=100)
            items = [_strip_mongo_id(d) for d in cursor]
        except TypeError as e:
            # Some fakes may not support 'limit' kwarg
            app.logger.warning("find(limit=) unsupported; falling back for credential_configs by email: %s", str(e))
            try:
                items = [_strip_mongo_id(d) for d in mdb["credential_configs"].find({"email": email})][:100]
            except Exception as e2:
                app.logger.error("Database find error on GET /credential_configs/by_email/%s: %s", email, str(e2),
                                 exc_info=True)
                return jsonify(error=str(e2)), 500
        except Exception as e:
            app.logger.error("Database find error on GET /credential_configs/by_email/%s: %s", email, str(e),
                             exc_info=True)
            return jsonify(error=str(e)), 500
        return jsonify(items), 200

    @app.route("/subscriptions/by_user_id/<path:user_id>", methods=["GET"])
    def get_subscriptions_by_user_id(user_id: str):
        app.logger.info("GET /subscriptions/by_user_id/%s", user_id)
        try:
            cursor = mdb["subscriptions"].find({"user_id": user_id}, limit=100)
            items = [_strip_mongo_id(d) for d in cursor]
        except TypeError as e:
            # Some fakes may not support 'limit' kwarg
            app.logger.warning("find(limit=) unsupported; falling back for subscriptions by user_id: %s", str(e))
            try:
                items = [_strip_mongo_id(d) for d in mdb["subscriptions"].find({"user_id": user_id})][:100]
            except Exception as e2:
                app.logger.error("Database find error on GET /subscriptions/by_user_id/%s: %s", user_id, str(e2),
                                 exc_info=True)
                return jsonify(error=str(e2)), 500
        except Exception as e:
            app.logger.error("Database find error on GET /subscriptions/by_user_id/%s: %s", user_id, str(e),
                             exc_info=True)
            return jsonify(error=str(e)), 500
        return jsonify(items), 200

    @app.route("/channels/by_creator_id/<path:creator_id>", methods=["GET"])
    def get_channels_by_creator_id(creator_id: str):
        app.logger.info("GET /channels/by_creator_id/%s", creator_id)
        try:
            cursor = mdb["channels"].find({"creator_id": creator_id}, limit=100)
            items = [_strip_mongo_id(d) for d in cursor]
        except TypeError as e:
            # Some fakes may not support 'limit' kwarg
            app.logger.warning("find(limit=) unsupported; falling back for subscriptions by creator_id: %s", str(e))
            try:
                items = [_strip_mongo_id(d) for d in mdb["channels"].find({"creator_id": creator_id})][:100]
            except Exception as e2:
                app.logger.error("Database find error on GET /channels/by_creator_id/%s: %s", creator_id, str(e2),
                                 exc_info=True)
                return jsonify(error=str(e2)), 500
        except Exception as e:
            app.logger.error("Database find error on GET /channels/by_creator_id/%s: %s", creator_id, str(e),
                             exc_info=True)
            return jsonify(error=str(e)), 500
        return jsonify(items), 200

    # Register all entities
    for name in ENTITIES.keys():
        register_crud_routes(name)

    return app


# Default app instance uses real Mongo (or env-configured)
app = create_app()

def _load_runtime_config():
    """
    Loads runtime configuration from:
      - TWILIGHT_DIGITAL_CONFIG env var (path to JSON), or
      - ./config/twilight_digital_api.json relative to this file.
    Returns {} if not found or invalid.
    """
    default_path = Path(__file__).parent / "config" / "twilight_digital_api.json"
    cfg_path = Path(os.environ.get("TWILIGHT_DIGITAL_CONFIG", str(default_path)))
    try:
        with cfg_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        app.logger.exception("Failed to load runtime config from %s", cfg_path)
        return {}

if __name__ == "__main__":
    cfg = _load_runtime_config()
    host = cfg.get("host", "0.0.0.0")
    port = int(cfg.get("port", 8080))
    external_url = cfg.get("url")
    if external_url:
        app.config["EXTERNAL_URL"] = external_url
    app.run(host=host, port=port, debug=False)
